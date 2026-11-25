# ЛИТЕРАТУРНЫЙ ОБЗОР (черновик v1 — для 1-й предзащиты)

**Тема:** Development of an Explainable Security Incident Prioritization Module for SIEM Based on Asset Context and Event Sequence Analysis

> Все источники ниже проверены (arXiv/первичные страницы). Формат ссылок — упрощённый; при финальном оформлении переведём в требуемый вузом (ГОСТ / IEEE).

---

## 1. Проблема: перегрузка алертами и приоритизация в SOC

Операционные центры безопасности (SOC) ежедневно сталкиваются с проблемой **alert fatigue** — потоком срабатываний, большинство из которых ложные или малозначимые, из-за чего реальные атаки теряются в шуме. Свежий обзор Ndichu и соавт. (2026), синтезировавший 119 работ по AI-поддержке SOC за 2015–2026 гг., фиксирует четыре направления автоматизации: фильтрация, триаж (приоритизация), корреляция и генеративная контекстуализация [Ndichu2026]. При этом обзор указывает на устойчивые пробелы: слабая операционная валидация методов, недостаточная робастность, отсутствие переносимости между окружениями и непоследовательная практика оценки. Это подтверждает актуальность задачи: автоматическая приоритизация инцидентов — признанное направление, но зрелых, проверяемых и объяснимых решений мало.

Uetz и соавт. (2026) провели первое систематическое исследование **risk-based alerting (RBA)** — подхода, встроенного в ряд коммерческих SIEM. Рефрейминг RBA как непрерывной приоритизации (а не бинарного порога) позволил им оценить 5 базовых «рисковых гипотез» на 8 датасетах: комбинации модулей достигли AUROC 0.92 против 0.72 у простой severity-приоритизации [Uetz2026]. Важный для нас вывод: контекстные рисковые сигналы действительно работают, но конфигурация в реальных системах до сих пор опирается на «анекдотические данные», а сам RBA рассматривается как базовая линия для более сложных методов. Наш модуль строится ровно на этой идее, но добавляет два измерения, которые в RBA обычно отсутствуют: последовательностный анализ событий и обязательную объяснимость.

## 2. Приоритизация алертов: ML-подходы и их ограничения

Ряд работ применяет машинное обучение непосредственно к задаче приоритизации. Gelman и соавт. (2023) предложили фреймворк TEQ, предсказывающий «actionability» алертов и инцидентов на реальных SOC-данных: снижение времени реакции на 22.9%, подавление 54% ложных срабатываний при детекции 95.1% [Gelman2023]. Однако работа не раскрывает, как учитывается контекст атакуемого актива и последовательность событий, и не предоставляет объяснений приоритета. Tong и соавт. (2019) и Chavali и соавт. (2022) формулируют приоритизацию как игру защитник–атакующий и решают её reinforcement learning'ом, получая робастные политики против адаптивного противника [Tong2019, Chavali2022]. Эти подходы интересны теоретически (противник учитывает политику приоритизации), но порождают нейросетевые политики, которые по построению не объяснимы для аналитика, а их обучение требует симуляционных окружений, недоступных в учебном проекте.

Новейшее направление — LLM-агенты для триажа. Tsegai и соавт. (2026) показали, что базовые агентные схемы пропускают более 40% атак, а их фреймворк AIDA (диалектическая проверка решения, «журнал расследования») достигает F1 = 0.958 [Tsegai2026]. Это сильный результат, но принципиально другой класс систем: он требует коммерческих LLM и интерактивных запросов к SIEM, что выходит за рамки и бюджет дипломного проекта. Для нас эта работа ценна как верхняя граница сравнения и источник наблюдения о важности «явного обоснования решения» — мы реализуем его через прозрачный скоринг вместо LLM-рассуждений.

## 3. Контекст актива: чему учит vulnerability prioritization

Ближайшая зрелая параллель к «asset context» — приоритизация уязвимостей. Классическая оценка CVSS даёт severity без контекста развёртывания. Jacobs и соавт. (2019, 2023) разработали **EPSS** — открытую data-driven модель, предсказывающую вероятность эксплуатации уязвимости в течение 12 месяцев; сообщество из 170+ экспертов улучшило качество ранжирования на 82% относительно прежних моделей [Jacobs2019, Jacobs2023]. Тем не менее EPSS статистичен и тоже контекстно-слеп к конкретной инфраструктуре. Podder и соавт. (2026) с двигателем **CAPE** напрямую атакуют этот пробел: они обогащают отчёты сканеров данными развёртывания и ранжируют CVE по достижимости, центральности и эксплуатируемости; на 30 приложениях (6138 CVE) большинство уязвимостей оказались и недостижимы, и неэксплуатируемы, и контекстное ранжирование превзошло CVSS/EPSS/KEV [Podder2026]. Koscinski и соавт. (2025) эмпирически показывают противоречивость самих скоринговых систем, а Hellsten и соавт. (2026) — их расхождение на пересечении данных [Koscinski2025, Hellsten2026].

**Перенос на нашу задачу:** логика CAPE (ранжируй не по абстрактной серьёзности, а по достижимости/центральности/эксплуатируемости *в конкретной среде*) напрямую переносится с уязвимостей на инциденты: приоритет алерта о попытке эксплуатации на критичном, уязвимом и центральном активе должен расти. Практически это реализуемо без ML: инвентаризация активов + CMDB-атрибуты + связка CVE↔EPSS.

## 4. Анализ последовательности событий: от kill chain к графам атак

Классическая модель стадий атаки — Cyber Kill Chain Хатчинса, Клопперта и Амина (2011): разведка, оружие, доставка, эксплуатация, установка, командование, действия по цели [Hutchins2011]. Её критикуют за периметрально-центричность и слабое покрытие инсайдерских атак; ответом стал **MITRE ATT&CK** (2013, актуальная v20, октябрь 2026) — открытый каталог тактик и техник противника с общей лексикой (T1566-Phishing и т.д.), ставший отраслевым стандартом и поддерживаемый CISA [MITRE2026]. ATT&CK — естественная система координат для оценки «фазы» атаки: позиция алерта на матрице тактик даёт понятный признак прогресса атаки (ранняя разведка vs. позднее воздействие).

Линия алерт-корреляции: обзор Mirheidari и соавт. (таксономия алгоритмов корреляции: цели — снижение ложных срабатываний, выявление высокоуровневых паттернов, предсказание состояния атаки; вывод — сильная корреляционная система должна комбинировать сильные стороны разных категорий) [Mirheidari2013]. Tedesco и Aickelin (2010) объединяют корреляцию и гипотезирование пропущенных алертов через типовые графы [Tedesco2010]. Landauer и соавт. (2023) публикуют **датасет мультишаговых атак** (3 IDS, 8 прогонов атаки + симулированные пользователи) и демонстрируют на нём приоритизацию алертов и извлечение графов атак [Landauer2023] — это готовая основа для воспроизводимой оценки нашего модуля на последовательностном признаке. Leal Díaz и соавт. (2023) визуализируют критические пути в графах атак (SAGE + дашборд с таймлайном и ATT&CK-матрицей), подтверждая практическую ценность критически-путевого представления для аналитиков [LealDiaz2023].

## 5. Объяснимость (XAI) в security

Базовые инструменты объяснения: **LIME** (Ribeiro et al., 2016) — локальные интерпретируемые аппроксимации любой модели; **SHAP** (Lundberg & Lee, 2017) — теоретически обоснованные аддитивные атрибуции значений признаков на основе векторов Шэпли, объединившие шесть более ранних методов [Ribeiro2016, Lundberg2017]. Применительно к IDС/alert-классификации Kalakoti и соавт. (2025) обучили LSTM-приоритизатор на реальных данных SOC и сравнили LIME, SHAP, Integrated Gradients и DeepLIFT по верности, сложности, робастности и надёжности: DeepLIFT стабильно выиграл, а ранжирования признаков совпали с ожиданиями SOC-аналитиков [Kalakoti2025]. Для нашей архитектуры ключевой вывод: если скоринговая модель конструируется как аддитивная (взвешенная сумма прозрачных факторов), XAI-слой не нужен как отдельный костыль — объяснение является самим скором («что именно и на сколько пунктов повысило приоритет»). SHAP остаётся опцией, если в модель добавятся ML-компоненты.

Отдельное направление — интерпретируемость как цель проектирования: многочисленные работы 2021–2026 по XAI-IDS (SHAP поверх ансамблей, автоэнкодеров, трансформеров) показывают широкий спрос, но в основном на датасетах сетевого трафика, а не на уровне инцидентов SIEM. Там же зафиксированы новые риски: Mia и Pritom (2025) демонстрируют атаки на сами XAI-объяснения [Mia2025], а Vourganas и Michala (2026) — фрагильность атрибуций из-за мультиколлинеарности признаков [Vourganas2026]. Это аргумент в пользу прозрачной by-design модели.

## 6. Синтез: пробелы и позиционирование проекта

| Направление | Что достигнуто | Чего не хватает | Что берём |
|---|---|---|---|
| Приоритизация алертов (ML/RL) | TEQ: -54% FP при 95% детекции [Gelman2023] | Нет asset context, нет объяснений | Постановку задачи, метрики (precision@k, доля подавленных FP) |
| Risk-based alerting | RBA: AUROC 0.92 vs 0.72 severity [Uetz2026] | «Конфигурация по анекдотам», слабая воспроизводимость, RBA = baseline | Идею контекстных рисковых модулей, RBA как baseline сравнения |
| Asset context (vuln mgmt) | CAPE: контекстное ранжирование > CVSS/EPSS/KEV [Podder2026] | Применено к CVE, не к инцидентам | Признаки: критичность/достижимость/центральность актива; EPSS |
| Event sequence | ATT&CK; корреляция, графы атак [MITRE2026, Landauer2023] | Последовательность редко входит в сам скор приоритета | ATT&CK-фазу как признак; датасет Landauer для оценки |
| Explainability | SHAP/LIME/DeepLIFT проверены на SOC-данных [Kalakoti2025] | XAI поверх «чёрных» моделей; уязвимость объяснений | Прозрачную аддитивную модель, где скор = объяснение |

**Интегрированный пробел:** ни одна из проверенных работ не объединяет одновременно (1) контекст актива, (2) последовательностный анализ событий и (3) объяснимость по построению в одном модуле приоритизации инцидентов для SIEM — и не реализует это в открытом, воспроизводимом виде для open-source платформы (например, Wazuh). Именно эту комбинацию предлагается реализовать и оценить в дипломном проекте, с RBA/severity как базовыми линиями и датасетом Landauer et al. как последовательностным тестбедом.

---

## Список источников (проверенные)

1. [Ndichu2026] Ndichu S., Ban T., Ozawa S., Takahashi T., Inoue D. AI-Driven Security Alert Screening and Alert Fatigue Mitigation in Security Operations Centers: A Survey. arXiv:2605.08316, 2026. https://arxiv.org/abs/2605.08316
2. [Uetz2026] Uetz R., Bönninghausen P., Hackländer-Jansen L., Henze M. Can Risk-Based Alerting Mitigate Cybersecurity Alert Fatigue? arXiv:2609.02465, 2026. https://arxiv.org/abs/2609.02465
3. [Gelman2023] Gelman B., Taoufiq S., Vörös T., Berlin K. That Escalated Quickly: An ML Framework for Alert Prioritization. arXiv:2302.06648, 2023. https://arxiv.org/abs/2302.06648
4. [Tong2019] Tong L., Laszka A., Yan C., Zhang N., Vorobeychik Y. Finding Needles in a Moving Haystack: Prioritizing Alerts with Adversarial Reinforcement Learning. arXiv:1906.08805, 2019. https://arxiv.org/abs/1906.08805
5. [Chavali2022] Chavali L., Gupta T., Saxena P. SAC-AP: Soft Actor Critic based Deep Reinforcement Learning for Alert Prioritization. arXiv:2207.13666, 2022. https://arxiv.org/abs/2207.13666
6. [Tsegai2026] Tsegai S. A., Kantchelian A., Yao D., Gao P. From Investigation Failures to Reliable SOC Agents: Understanding and Improving LLM-Based Alert Triage. arXiv:2610.10608, 2026. https://arxiv.org/abs/2610.10608
7. [Jacobs2019] Jacobs J., Romanosky S., Edwards B., Roytman M., Adjerid I. Exploit Prediction Scoring System (EPSS). arXiv:1908.04856, 2019. https://arxiv.org/abs/1908.04856
8. [Jacobs2023] Jacobs J., Romanosky S., Suciu O., Edwards B., Sarabi A. Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights. arXiv:2302.14172, 2023. https://arxiv.org/abs/2302.14172
9. [Podder2026] Podder R., Koscinski V., Ray I. CAPE - Context-Aware Prioritization Engine for Vulnerability Scoring and Management. arXiv:2610.13071, 2026. https://arxiv.org/abs/2610.13071
10. [Koscinski2025] Koscinski V., Nelson M., Okutan A., Falso R., Mirakhorli M. Conflicting Scores, Confusing Signals: An Empirical Study of Vulnerability Scoring Systems. arXiv:2508.13644, 2025. https://arxiv.org/abs/2508.13644
11. [Hellsten2026] Hellsten K., Herttuainen J., Kam A., Johnson A., Welsh D., Kaski K. When Cyber Scoring Systems Diverge: An Empirical Comparison. arXiv:2609.37217, 2026. https://arxiv.org/abs/2609.37217
12. [Hutchins2011] Hutchins E. M., Cloppert M. J., Amin R. M. Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains. Lockheed Martin, 2011.
13. [MITRE2026] MITRE. ATT&CK Framework (v20). https://attack.mitre.org/, 2026.
14. [Mirheidari2013] Mirheidari S. A., Arshad S., Jalili R. Alert Correlation Algorithms: A Survey and Taxonomy. arXiv:1811.00921 (CSS 2013), 2018. https://arxiv.org/abs/1811.00921
15. [Tedesco2010] Tedesco G., Aickelin U. Real-Time Alert Correlation with Type Graphs. Proceedings of ICISS 2008, LNCS 5352, pp. 173–187 (arXiv:1004.4089), 2010. https://arxiv.org/abs/1004.4089
16. [Landauer2023] Landauer M., Skopik F., Wurzenberger M. Introducing a New Alert Data Set for Multi-Step Attack Analysis. CSET 2024 (arXiv:2308.12627), 2023. https://arxiv.org/abs/2308.12627 | Датасет: AIT-ADS, Zenodo DOI 10.5281/zenodo.8263181 (CC-BY-4.0).
17. [LealDiaz2023] Leal Díaz S., Pastrana S., Nadeem A. Critical Path Prioritization Dashboard for Alert-driven Attack Graphs. arXiv:2310.13079, 2023. https://arxiv.org/abs/2310.13079
18. [Ribeiro2016] Ribeiro M. T., Singh S., Guestrin C. "Why Should I Trust You?": Explaining the Predictions of Any Classifier. KDD 2016 (arXiv:1602.04938), 2016. https://arxiv.org/abs/1602.04938
19. [Lundberg2017] Lundberg S. M., Lee S.-I. A Unified Approach to Interpreting Model Predictions. NIPS 2017 (arXiv:1705.07874), 2017. https://arxiv.org/abs/1705.07874
20. [Kalakoti2025] Kalakoti R., Vaarandi R., Bahsi H., Nõmm S. Evaluating explainable AI for deep learning-based network intrusion detection system alert classification. ICISSP 2025 (arXiv:2506.07882), 2025. https://arxiv.org/abs/2506.07882
21. [Mia2025] Mia M., Pritom M. M. A. Explainable but Vulnerable: Adversarial Attacks on XAI Explanation in Cybersecurity Applications. IEEE-TPS 2025 (arXiv:2510.03623), 2025. https://arxiv.org/abs/2510.03623
22. [Vourganas2026] Vourganas I. J., Michala A. L. Stabilising Explainability Fragility in Cybersecurity AI: The Impact and Mitigation of Multicollinearity in Public Benchmark Datasets. arXiv:2605.22529, 2026. https://arxiv.org/abs/2605.22529
