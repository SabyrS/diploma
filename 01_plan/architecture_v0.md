# АРХИТЕКТУРА И СКОРИНГОВАЯ МОДЕЛЬ МОДУЛЯ ESPM (v0.2 — для 1-й предзащиты)

**Название модуля:** ESPM — Explainable Security Incident Prioritization Module
**Авторы:** Сабыр (Sabyr) и Владимир (Vladimir)

---

## 1. Концептуальная схема конвейера (5-Stage Pipeline)

```
 Wazuh SIEM (alerts.json) ──► [1] Ingestion & Normalization (Владимир)
                                    │  (Потоковый JSONL-парсер → унифицированный Alert:
                                    │   ts, host, location, agent_ip, rule_id, level, groups)
                                    ▼
                              [2] Location-Aware Asset Context Enrichment (Сабыр)
                                    │  ((host, location) → CMDB Asset Profile:
                                    │   canonical asset_id, criticality, EPSS vulnerability, centrality)
                                    ▼
                              [3] Event Sequence & Kill-Chain Analysis (Владимир)
                                    │  (Мэппинг правил → MITRE ATT&CK v20 stage & tactic;
                                    │   O(1) 600s time-bucketed burst rate + 3600s kill-chain memory)
                                    ▼
                              [4] Additive Explainable Scoring Engine (Сабыр)
                                    │  Priority = 100 · clamp( Σ w_i · f_i / Σ w_i )
                                    │  Детерминированный расчёт вклада каждого фактора c_i = w_i · f_i
                                    ▼
                              [5] Explanation Renderer & SOC Dashboard (Сабыр)
                                    │  (Ранжированный JSON-объект объяснения + текстовое резюме:
                                    │   «+28.5 pts: MITRE Privilege Escalation; +15.0 pts: 5 стадий kill-chain...»)
                                    ▼
                              Приоритизированная очередь инцидентов + Веб-дашборд SOC (dashboard.html)
```

---

## 2. Спецификация компонентов и распределение ответственности

| № | Компонент | Входные данные | Выходные данные | Алгоритмы и структуры данных | Ответственный |
|---|---|---|---|---|---|
| 1 | **Ingestion & Normalization** | Поток `alerts.json` / `*_wazuh.json` (JSONL) | Объект `Alert(ts, host, location, agent_ip, rule_id, level, groups, description, full_log)` | Потоковый генератор Python (`parse_wazuh_jsonl`), устойчивый к битым строкам, конвертация ISO-8601 в Unix epoch | **Владимир** |
| 2 | **Asset Context Enrichment (CMDB)** | Пара `(alert.host, alert.location)` + справочник CMDB/EPSS | Объект `Asset(role, criticality, vulnerability, centrality)` и канонический ключ актива `hkey` | Location-aware резолвинг: объединяет веб-логи `/var/log/apache2/intranet*` и системные логи `/var/log/auth.log` в единый актив `intranet-server` | **Сабыр** |
| 3 | **Event Sequence Analysis** | Нормализованный `Alert` + история актива `hkey` | `stage`, `tactic` (MITRE ATT&CK v20), факторы $f_{\text{phase}}, f_{\text{prog}}, f_{\text{chain}}$ | Кольцевая очередь секундных корзин `deque([sec, count, max_phase])` (600 с) + хеш-таблица активных фаз атаки `_stage_memory` (3600 с) со сложностью $O(1)$ | **Владимир** |
| 4 | **Scoring Engine** | 7 нормированных факторов $f_i \in [0, 1]$ + вектор весов $w_i$ | Итоговый приоритет `priority` $\in [0, 100]$ и вектор вкладов `contrib` | Линейно-аддитивная композиция с нормировкой весов (Explainability by Design, Faithfulness = 1.0) | **Сабыр** |
| 5 | **Explanation Renderer & Web UI** | Объект `ScoredAlert` | Машинно-читаемый `explanation_example.json` + интерактивный интерфейс `dashboard.html` | Сортировка факторов по убыванию $w_i f_i$, генерация текстовых обоснований `why`, интерактивный What-If симулятор | **Сабыр** |

---

## 3. Математическая формализация скоринговой модели

Для каждого входящего алерта $a$ в момент времени $t$ на активе $u = \text{resolve}(a.\text{host}, a.\text{location})$ вычисляется 7 интерпретируемых факторов $f_i(a, u, \mathcal{H}_u(t)) \in [0, 1]$:

### Группа A — Контекст актива (перенос принципов CAPE [Podder2026] и EPSS [Jacobs2023]):
1. **`f_asset_criticality`** ($w_1 = 0.15$): бизнес-критичность целевого узла/сервиса в инфраструктуре организации (например, `0.95` для целевого корпоративного портала `intranet-server`, `0.55` для почтового сервера, `0.35` для пассивного сенсора `network-ids-sensor`, `0.10` для внешних узлов).
2. **`f_asset_vulnerability`** ($w_2 = 0.10$): максимальная оценка эксплуатируемости уязвимостей узла по шкале EPSS / наличию критических CVE (в AIT-ADS `intranet-server` содержит уязвимый плагин WordPress wpDiscuz CVE-2020-24186 $\rightarrow 0.90$).
3. **`f_asset_centrality`** ($w_3 = 0.05$): топологическая центральность узла и потенциал бокового перемещения (Lateral Movement) к соседним сегментам сети.

### Группа B — Анализ последовательности событий (MITRE ATT&CK v20 [MITRE2026]):
4. **`f_attack_phase`** ($w_4 = 0.30$): нормированная глубина продвижения атаки по цепочке тактик MITRE ATT&CK:
   - Фоновая штатная активность (`routine_auth` Dovecot level 3, `av_update` ClamAV): $0.05$;
   - Пассивные сетевые сигналы (`ids_signal` Suricata TLS): $0.12$;
   - Активная разведка (`Reconnaissance` — `web_scan`, `wpscan`, `dirb`, `nmap`): $0.65$;
   - Перебор учётных данных (`Credential Access` — `cracking`, `authentication_failed`): $0.60$;
   - Обход защиты и первичный доступ (`Defense Evasion` / `Initial Access` — `access_denied`, `web_attack`, `webshell`): $0.75\text{–}0.80$;
   - Выполнение кода и открытие сессии на целевом сервере (`Execution` — `pam` на `intranet-server`): $0.85$;
   - Повышение привилегий (`Privilege Escalation` — `sudo`, `su`, `audit`): $0.95$.
5. **`f_attack_progression`** ($w_5 = 0.10$): отношение краткосрочной интенсивности потока алертов на активе $u$ в скользящем окне $\Delta t = 600\text{ с}$ к долгосрочной базовой частоте этого актива, дополненное индикатором перехода в фазу пост-эксплуатации ($f_{\text{phase}} \ge 0.85$ при наличии предшествующих стадий).
6. **`f_chain_evidence`** ($w_6 = 0.15$): индикатор многоступенчатой корреляции на активе $u$ в горизонте памяти цепочки $\Delta T_{\text{chain}} = 3600\text{ с}$:
   $$f_{\text{chain}} = \begin{cases} 1.0, & \text{если на активе } u \text{ уже зафиксированы другие активные фазы атаки } (f_{\text{phase}} \ge 0.60) \text{ или более поздняя стадия}, \\ 0.6, & \text{если в окне } 600\text{ с есть предшествующие срабатывания однотипного уровня}, \\ 0.0, & \text{если алерт изолирован.} \end{cases}$$

### Группа C — Базовая оценка SIEM:
7. **`f_severity`** ($w_7 = 0.15$): нормированный уровень правила Wazuh $f_{\text{sev}} = \min(1.0, \text{rule.level} / 15.0)$.

### Итоговый скор и структура объяснения:
$$\text{Priority}(a) = 100 \cdot \min\left(1.0, \frac{\sum_{i=1}^{7} w_i \cdot f_i}{\sum_{i=1}^{7} w_i}\right)$$
Объяснение для SOC-аналитика формируется непосредственно из слагаемых:
$$\text{Explanation}(a) = \text{sort}_{\text{desc}}\Big(\big\{\big(\text{factor}_i,\; f_i,\; c_i = w_i f_i,\; \text{why}_i\big)\big\}_{i=1}^{7}\Big)$$
Благодаря линейно-аддитивной структуре сумма вкладов $\sum c_i$ в точности равна итоговому приоритету — отсутствуют ошибки аппроксимации и уязвимости к состязательным атакам на XAI, выявленные в [Mia2025, Vourganas2026].

---

## 4. Обоснование выбора технологического стека

- **Wazuh SIEM (Open-Source):** промышленный стандарт среди открытых SIEM/XDR систем, использующий JSON-формат оповещений с встроенной классификацией групп правил; датасет AIT-ADS напрямую содержит реальные срабатывания Wazuh.
- **Python 3.10+ (Standard Library для ядра):** отсутствие тяжёлых внешних зависимостей в `scoring.py` гарантирует мгновенное развёртывание модуля как легковесного демона/коннектора на любом сервере Wazuh Manager и высокую скорость обработки (~70 000 алертов/сек в одном потоке).
- **MITRE ATT&CK v20:** общепринятая таксономия стадий атаки, понятная любому SOC-аналитику.
- **HTML5 / Vanilla JS Dashboard (`dashboard.html`):** автономный визуальный интерфейс очереди инцидентов и симулятора объяснений, работающий без необходимости поднимать сложный фронтенд-стек.
