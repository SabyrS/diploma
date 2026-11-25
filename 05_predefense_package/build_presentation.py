"""Generate the 13-slide PowerPoint presentation for the 1st Pre-Defense (with embedded charts & all 8 scenarios):
05_predefense_package/PreDefense_1_Presentation_ESPM.pptx
"""
from pathlib import Path
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

BG_DARK = RGBColor(11, 16, 32)
CARD_BG = RGBColor(20, 29, 56)
CARD_BORDER = RGBColor(45, 65, 115)
ACCENT = RGBColor(56, 189, 248)
ACCENT_GREEN = RGBColor(74, 222, 128)
ACCENT_WARN = RGBColor(250, 204, 21)
ACCENT_RED = RGBColor(248, 113, 113)
WHITE = RGBColor(245, 248, 255)


def set_bg(slide):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = BG_DARK


def add_header(slide, title_text, subtitle_text, speaker_badge=""):
    tb = slide.shapes.add_textbox(Inches(0.5), Inches(0.32), Inches(9.8), Inches(0.88))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = title_text
    p.font.size = Pt(23)
    p.font.bold = True
    p.font.color.rgb = WHITE

    p2 = tf.add_paragraph()
    p2.text = subtitle_text
    p2.font.size = Pt(11.5)
    p2.font.color.rgb = ACCENT

    if speaker_badge:
        badge = slide.shapes.add_shape(
            MSO_SHAPE.ROUNDED_RECTANGLE, Inches(10.3), Inches(0.36), Inches(2.5), Inches(0.46)
        )
        badge.fill.solid()
        badge.fill.fore_color.rgb = CARD_BG
        badge.line.color.rgb = ACCENT
        btf = badge.text_frame
        bp = btf.paragraphs[0]
        bp.text = speaker_badge
        bp.alignment = PP_ALIGN.CENTER
        bp.font.size = Pt(10.5)
        bp.font.bold = True
        bp.font.color.rgb = ACCENT


def add_card(slide, left, top, width, height, title, bullets, title_color=ACCENT):
    shape = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height)
    )
    shape.fill.solid()
    shape.fill.fore_color.rgb = CARD_BG
    shape.line.color.rgb = CARD_BORDER

    tb = slide.shapes.add_textbox(
        Inches(left + 0.18), Inches(top + 0.14), Inches(width - 0.36), Inches(height - 0.28)
    )
    tf = tb.text_frame
    tf.word_wrap = True
    p0 = tf.paragraphs[0]
    p0.text = title
    p0.font.size = Pt(13.5)
    p0.font.bold = True
    p0.font.color.rgb = title_color

    for b in bullets:
        p = tf.add_paragraph()
        p.text = "• " + b
        p.font.size = Pt(11)
        p.font.color.rgb = WHITE
        p.space_before = Pt(4)


def add_table_card(slide, left, top, width, height, headers, rows, col_widths=None):
    table_shape = slide.shapes.add_table(
        len(rows) + 1, len(headers), Inches(left), Inches(top), Inches(width), Inches(height)
    )
    table = table_shape.table
    if col_widths:
        for i, w in enumerate(col_widths):
            table.columns[i].width = Inches(w)

    for c_idx, h in enumerate(headers):
        cell = table.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(30, 45, 85)
        p = cell.text_frame.paragraphs[0]
        p.text = h
        p.font.size = Pt(10)
        p.font.bold = True
        p.font.color.rgb = ACCENT

    for r_idx, row in enumerate(rows):
        for c_idx, val in enumerate(row):
            cell = table.cell(r_idx + 1, c_idx)
            cell.fill.solid()
            cell.fill.fore_color.rgb = CARD_BG if r_idx % 2 == 0 else RGBColor(16, 23, 44)
            p = cell.text_frame.paragraphs[0]
            p.text = str(val)
            p.font.size = Pt(9.5)
            p.font.color.rgb = WHITE


def build():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank = prs.slide_layouts[6]

    # SLIDE 1: TITLE
    s1 = prs.slides.add_slide(blank)
    set_bg(s1)
    add_card(
        s1, 0.8, 0.9, 11.7, 5.7,
        "ASTANA IT UNIVERSITY • 1-Я ПРЕДЗАЩИТА ДИПЛОМНОГО ПРОЕКТА (2026–2027)",
        [
            "Тема: Development of an Explainable Security Incident Prioritization Module for SIEM Based on Asset Context and Event Sequence Analysis",
            "Разработка объяснимого модуля приоритизации инцидентов безопасности для SIEM на основе контекста активов и анализа последовательности событий",
            "Команда проекта: Сабыр (Sabyr) и Владимир (Vladimir)",
            "Целевая платформа: Open-Source SIEM Wazuh • Бенчмарк: AIT-ADS (все 8 сценариев, 2 600 263 алерта Wazuh, CC-BY-4.0)",
            "Готовность к 1-й предзащите: Литобзор (22 статьи, проверено через arXiv/OpenAlex API) + Прототип ESPM v0.2 (Macro AUROC 0.967, AP 0.948 на 2.60 млн алертов) + Веб-дашборд SOC + Скомпилированный PDF диплома в LaTeX"
        ],
        title_color=ACCENT
    )

    # SLIDE 2: RELEVANCE & PROBLEM
    s2 = prs.slides.add_slide(blank)
    set_bg(s2)
    add_header(s2, "1. Актуальность и конкретная проблема", "Почему стандартная приоритизация в SIEM пропускает многошаговые атаки", "Докладчик: Сабыр")
    add_card(s2, 0.5, 1.35, 4.0, 5.6, "1. Контекстная слепота к активу", [
        "В штатном SIEM приоритет = rule.level (0..15) без учёта того, КАКОЙ актив атакован.",
        "Попытка эксплойта на критичном сервере с CVE и на тестовой машине получают одинаковый скор.",
        "В управлении уязвимостями контекстный движок CAPE (Podder et al., 2026) доказал кратный прирост точности, но к инцидентам SIEM не применялся."
    ], ACCENT_WARN)
    add_card(s2, 4.65, 1.35, 4.0, 5.6, "2. Слепота к последовательности", [
        "Атака идёт по стадиям MITRE ATT&CK, но SIEM оценивает каждый алерт изолированно.",
        "Реальный факт из AIT-ADS: захват root-прав (Rule 5402: sudo to ROOT и Rule 5304: su UID change) имеет в Wazuh level = 3!",
        "Фоновый шум Suricata TLS имеет level = 6. Итог: захват ROOT падает на #22 449 – #492 376 место в очереди!"
    ], ACCENT_RED)
    add_card(s2, 8.8, 1.35, 4.0, 5.6, "3. Необъяснимость ML и XAI-риски", [
        "Нейросети и RL-политики (Tong 2019, SAC-AP 2022) — «чёрный ящик» для аналитика SOC.",
        "Post-hoc методы SHAP и LIME уязвимы к fairwashing-атакам (Mia 2025) и нестабильны при мультиколлинеарности (Vourganas 2026).",
        "Проблема: нет открытого модуля для Wazuh, объединяющего Asset Context + Event Sequence + Explainability by Design."
    ], ACCENT)

    # SLIDE 3: GOAL, TASKS, SCOPE
    s3 = prs.slides.add_slide(blank)
    set_bg(s3)
    add_header(s3, "2. Цель, задачи, объект, предмет и границы проекта", "Чёткая постановка исследования и зоны ответственности команды", "Докладчик: Сабыр")
    add_card(s3, 0.5, 1.35, 6.1, 5.6, "Цель, Объект, Предмет и Гипотезы", [
        "Цель: Разработать и оценить объяснимый модуль приоритизации инцидентов ESPM для Wazuh SIEM, повышающий качество ранжирования многошаговых атак (AUROC, AP, P@k) за счёт учёта контекста актива и последовательности событий.",
        "Объект: процессы триажа и приоритизации инцидентов в SIEM.",
        "Предмет: методы агрегации контекста активов (CMDB/EPSS) и стадий MITRE ATT&CK с объяснимостью по построению.",
        "Гипотеза H1: ESPM превзойдёт Severity-baseline по AUROC/AP и выведет события Privilege Escalation (level=3) в топ очереди.",
        "Гипотеза H2: Аддитивная декомпозиция скора обеспечит 100% верность объяснения (Faithfulness = 1.0, τ = 1.0)."
    ], ACCENT)
    add_card(s3, 6.75, 1.35, 6.05, 5.6, "5 Задач и Границы проекта (Scope)", [
        "Задача 1 (Сабыр + Владимир): Систематический литобзор (22 статьи) и выделение Research Gap.",
        "Задача 2 (Владимир): Анализ и подготовка всех 8 сценариев AIT-ADS (2.60M алертов Wazuh, Design + Blind Test).",
        "Задача 3 (Сабыр): Формализация 7-факторной модели (Asset Context + Sequence + Explainability).",
        "Задача 4 (Сабыр + Владимир): Реализация прототипа ESPM v0.2, O(1) ядра и веб-дашборда SOC.",
        "Задача 5 (Владимир + Сабыр): Оценка и ablation study на всех 8 сценариях против Severity и RBA.",
        "Границы: Входит надстройка над Wazuh + CMDB + веб-UI; НЕ входит переписывание сигнатур IDS и платные облачные LLM."
    ], ACCENT_GREEN)

    # SLIDE 4: LITERATURE REVIEW
    s4 = prs.slides.add_slide(blank)
    set_bg(s4)
    add_header(s4, "3. Литературный обзор (22 научных источника)", "95.5% рецензируемые статьи и труды конференций (верифицировано через arXiv/OpenAlex)", "Докладчик: Владимир")
    add_card(s4, 0.5, 1.35, 6.1, 5.6, "Систематизация по 5 научным направлениям", [
        "1. Alert Fatigue & RBA: Ndichu et al. (2026, обзор 119 работ), Uetz et al. (2026 — RBA даёт AUROC 0.92 против 0.72 у severity, но без последовательностей).",
        "2. ML/RL & LLM Triage: TEQ (Gelman 2023, -54% FP), Adversarial RL (Tong 2019, Chavali 2022 — чёрный ящик), AIDA (Tsegai 2026 — мультиагентный LLM, F1=0.958, но дорого для потока SIEM).",
        "3. Asset Context (Vuln Mgmt): EPSS (Jacobs 2019, 2023), CAPE (Podder 2026 — достижимость + центральность + EPSS лучше CVSS), Koscinski (2025), Hellsten (2026).",
        "4. Event Sequence & Attack Graphs: Cyber Kill Chain (2011), MITRE ATT&CK v20 (2026), Mirheidari (2013), Tedesco (2010), Landauer (2023 — AIT-ADS), Leal Díaz (2023 — SAGE).",
        "5. XAI в ИБ: LIME (2016), SHAP (2017), Kalakoti (2025), Mia (2025 — атаки на XAI), Vourganas (2026 — хрупкость из-за мультиколлинеарности)."
    ], ACCENT)
    add_card(s4, 6.75, 1.35, 6.05, 5.6, "Выявленный Research Gap (Научный пробел)", [
        "Пробел 1: RBA в SIEM учитывает базовый риск хоста, но игнорирует стадийность атаки по MITRE ATT&CK — поздние тихие фазы (sudo level=3) теряются в шуме сканов (медианный ранг #210 515!).",
        "Пробел 2: Передовые модели контекста (CAPE, EPSS) применялись только к статическим CVE-уязвимостям, но не к потоку инцидентов в open-source SIEM.",
        "Пробел 3: Post-hoc XAI (SHAP/LIME) поверх нейросетей уязвим к манипуляциям и мультиколлинеарности.",
        "Наше решение (ESPM): Первое объединение (1) контекста актива CAPE/EPSS + (2) анализа последовательностей ATT&CK + (3) объяснимости по построению для Wazuh SIEM."
    ], ACCENT_WARN)

    # SLIDE 5: COMPARISON TABLE
    s5 = prs.slides.add_slide(blank)
    set_bg(s5)
    add_header(s5, "4. Сравнительная матрица существующих решений и моделей", "Позиционирование модуля ESPM относительно 6 классов подходов", "Докладчик: Владимир")
    add_table_card(
        s5, 0.5, 1.35, 12.3, 5.5,
        ["Класс подхода / Модель", "Контекст актива (CMDB/EPSS)", "Последовательность (ATT&CK)", "Объяснимость (XAI)", "Сложность / Стоимость", "Macro AUROC / AP (8 сцен.)"],
        [
            ["1. Static Severity (Wazuh rule.level)", "Нет (слеп к активу)", "Нет (изолированно)", "Только текст правила", "O(1), встроено", "0.688 / 0.572 (Root #247k)"],
            ["2. Risk-Based Alerting (Uetz 2026)", "Да (вес хоста)", "Слабо (нет памяти стадий)", "Частичная", "O(1)", "0.955 / 0.903 (Root #210k)"],
            ["3. Supervised ML + SHAP (Kalakoti 2025)", "Косвенно", "Через окна LSTM", "Post-hoc (уязвимо!)", "Требует разметки SOC", "Непереносимо без разметки"],
            ["4. Deep RL (Tong 2019, Chavali 2022)", "В рамках симулятора", "Через состояния MDP", "Нет (чёрный ящик)", "Высокая (симулятор)", "Неприменимо в live SIEM"],
            ["5. Multi-Agent LLM (AIDA, Tsegai 2026)", "Через промпты", "Через журнал агентов", "Текстовый отчёт LLM", "Дорого и медленно", "Вне бюджета на 2.6M событий"],
            ["6. Vuln Context (CAPE 2026, EPSS 2023)", "Да (критичность, EPSS)", "Нет (только для CVE)", "Прозрачные факторы", "Статический расчёт", "Только для CVE-сканеров"],
            ["7. Модуль ESPM (Наше решение)", "Да (Location-Aware CMDB)", "Да (ATT&CK + O(1) память)", "By Design (Faithfulness=1)", "O(1), 32k–79k алерт/с", "0.967 / 0.948 (Root #1.5!)"]
        ],
        col_widths=[2.6, 2.0, 2.0, 2.0, 1.8, 1.9]
    )

    # SLIDE 6: DATASET
    s6 = prs.slides.add_slide(blank)
    set_bg(s6)
    add_header(s6, "5. Датасет и структура данных (AIT-ADS — все 8 сценариев)", "Открытый верифицированный бенчмарк мультишаговых атак (CC-BY-4.0)", "Докладчик: Владимир")
    add_card(s6, 0.5, 1.35, 5.7, 5.6, "Характеристики AIT-ADS (Landauer et al., 2023)", [
        "Источник: Zenodo DOI 10.5281/zenodo.8263181 (лицензия CC-BY-4.0, использование и публикация полностью разрешены, PII отсутствуют).",
        "Проверено в PoC v0.2: ВСЕ 8 сценариев Wazuh — 2 600 263 валидных хронологических алерта (~2.86 ГБ JSONL).",
        "Цепочка атаки (80 меток в labels.csv): network_scans -> service_scans -> dirb/wpscan -> webshell (CVE-2020-24186) -> cracking -> reverse_shell -> privilege_escalation (su/sudo) -> dnsteal.",
        "Честный протокол: свежий инстанс скорера на каждый сценарий; harrison и wheeler (1.19M алертов) — слепой тест (Blind Test).",
        "Резервный датасет: AIT-LDS v2.1 (сырые логи) + Docker-стенд Wazuh."
    ], ACCENT)
    add_table_card(
        s6, 6.35, 1.35, 6.45, 5.6,
        ["Сценарий", "Роль (Split)", "Алертов Wazuh", "Атаки (%)", "Root-событий"],
        [
            ["russellmitchell", "Design / Eval", "41 488", "20.6%", "3 (su/sudo)"],
            ["shaw", "Design / Eval", "68 539", "8.7%", "4 (su/sudo)"],
            ["wardbeck", "Design / Eval", "88 204", "6.9%", "4 (su/sudo)"],
            ["santos", "Design / Eval", "126 513", "7.6%", "4 (su/sudo)"],
            ["fox", "Design / Eval", "462 523", "89.1%", "4 (su/sudo)"],
            ["wilson", "Design / Eval", "625 303", "69.1%", "4 (su/sudo)"],
            ["harrison", "Blind Test 1", "583 754", "72.3%", "5 (su/sudo)"],
            ["wheeler", "Blind Test 2", "603 939", "69.7%", "4 (10ч пауза)"],
            ["ИТОГО (Все 8)", "6 Design + 2 Blind", "2 600 263", "66.1%", "32 события"]
        ],
        col_widths=[1.45, 1.35, 1.3, 1.0, 1.35]
    )

    # SLIDE 7: METHODOLOGY & SCORING MODEL
    s7 = prs.slides.add_slide(blank)
    set_bg(s7)
    add_header(s7, "6. Методология и математическая модель скоринга ESPM", "Линейно-аддитивная прозрачная модель 7 факторов: Priority = 100 · Σ (wᵢ · fᵢ) / Σ wᵢ", "Докладчик: Сабыр")
    add_card(s7, 0.5, 1.35, 4.0, 5.6, "Группа A: Контекст актива (Σw = 0.30)", [
        "Location-Aware CMDB: резолвинг актива по паре (host, location) — связывает логи Apache и /var/log/auth.log единого сервера intranet-server.",
        "1. f_asset_criticality (w=0.15): критичность бизнеса (0.95 intranet-server, 0.55 mail, 0.35 IDS-сенсор).",
        "2. f_asset_vulnerability (w=0.10): экспозиция уязвимостей EPSS / CVE-2020-24186 (0.90).",
        "3. f_asset_centrality (w=0.05): центральность в топологии сети (0.85)."
    ], ACCENT)
    add_card(s7, 4.65, 1.35, 4.0, 5.6, "Группа B: Последовательность (Σw = 0.55)", [
        "4. f_attack_phase (w=0.30): глубина тактики по MITRE ATT&CK v20 (0.05 routine_auth -> 0.65 Recon -> 0.80 Initial Access -> 0.95 PrivEsc).",
        "5. f_attack_progression (w=0.10): всплеск частоты в окне 600 с относительно базовой линии хоста.",
        "6. f_chain_evidence (w=0.15): память стадий за 3600 с (=1.0, если на активе уже шли предыдущие фазы атаки)."
    ], ACCENT_GREEN)
    add_card(s7, 8.8, 1.35, 4.0, 5.6, "Группа C + Explainability by Design", [
        "7. f_severity (w=0.15): базовый уровень правила Wazuh min(1.0, level / 15).",
        "Объяснение = сам скор: для каждого инцидента выдаётся ранжированный список {factor, value, contribution = wᵢ·fᵢ, why}.",
        "100% математическая точность (Faithfulness = 1.0) и защита от атак на XAI (Mia 2025) и коллинеарности (Vourganas 2026)."
    ], ACCENT_WARN)

    # SLIDE 8: ARCHITECTURE & STACK
    s8 = prs.slides.add_slide(blank)
    set_bg(s8)
    add_header(s8, "7. Архитектура конвейера ESPM и обоснование стека", "Потоковая обработка со сложностью O(1) на событие (32 050 – 79 458 алертов/сек)", "Докладчик: Сабыр")
    add_table_card(
        s8, 0.5, 1.35, 12.3, 3.6,
        ["Этап конвейера", "Вход", "Алгоритм и структура данных", "Выход", "Ответственный"],
        [
            ["[1] Ingestion & Normalization", "Wazuh JSONL (alerts.json)", "Потоковый генератор parse_wazuh_jsonl, фильтрация сбоев", "Унифицированный Alert", "Владимир"],
            ["[2] Asset Context Enrichment", "(alert.host, alert.location)", "Location-Aware CMDB + профили EPSS / критичности", "Asset + канонический ключ", "Сабыр"],
            ["[3] Event Sequence Analysis", "Alert + история актива", "O(1) 1-сек корзины deque (600с) + словарь стадий (3600с)", "stage, tactic, f_phase, f_chain", "Владимир"],
            ["[4] Additive Scoring Engine", "7 факторов f_i + веса w_i", "Нормированная взвешенная сумма Σ w_i f_i", "Priority ∈ [0..100]", "Сабыр"],
            ["[5] Explanation & Web UI", "ScoredAlert", "Сортировка вкладов c_i, рендеринг JSON + dashboard.html", "Очередь SOC + объяснение", "Сабыр"]
        ],
        col_widths=[2.5, 2.1, 3.8, 2.3, 1.6]
    )
    add_card(s8, 0.5, 5.15, 12.3, 1.75, "Обоснование выбора технологического стека", [
        "Wazuh SIEM (Open-Source): бесплатная промышленная платформа с открытой JSON-схемой алертов (в отличие от закрытого коммерческого Splunk RBA).",
        "Python 3.10+ (Zero External Dependencies для ядра): мгновенная интеграция на сервере Wazuh Manager, потребление RAM < 1 МБ, скорость до 79.5k алертов/сек.",
        "MITRE ATT&CK v20 + HTML5/JS Web Dashboard: стандартная для аналитиков SOC таксономия и наглядный интерактивный интерфейс с What-If симулятором."
    ], ACCENT)

    # SLIDE 9: POC IMPLEMENTATION DEMO
    s9 = prs.slides.add_slide(blank)
    set_bg(s9)
    add_header(s9, "8. Демонстрация начального этапа реализации (PoC v0.2)", "Что уже реализовано в коде (04_prototype/espm/) и протестировано", "Докладчик: Владимир")
    add_card(s9, 0.5, 1.35, 6.0, 5.6, "Реализованные программные модули", [
        "scoring.py (280 строк): полное ядро парсинга, Location-Aware CMDB, мэппинга MITRE ATT&CK, O(1) корзин окна и скоринга.",
        "evaluate.py (195 строк): честный прогон всех 8 сценариев + 2 абляции, расчёт AUROC, Average Precision (AP), P@10%, R@10% и Root Escalation Rank.",
        "test_espm.py (31 unit-тест): 31 passed, 0 failed за 1 секунду.",
        "demo_explanation.py + explanation_example.json: CLI-вывод топ-очереди и генерация машинно-читаемого JSON-объяснения.",
        "dashboard.html: интерактивный веб-дашборд аналитика SOC с декомпозицией факторов и симулятором скоринга."
    ], ACCENT_GREEN)
    add_card(s9, 6.7, 1.35, 6.1, 5.6, "Пример реального вывода ESPM v0.2 (russellmitchell)", [
        "Ранг #1–#2 из 41 488 алертов: priority = 84.0 [ATTACK: Privilege Escalation]",
        "Алерт: host=intranet-server, rule=5402, Wazuh level=3 (в базовом SIEM — 20 баллов из 100, ранг #29 261!)",
        "Лог: sudo: jhall : TTY=pts/1 ; PWD=/var/www/intranet ... COMMAND=/bin/bash",
        "Машинно-читаемое объяснение (почему приоритет 84.0):",
        "  +28.5 pts : attack_phase = Privilege Escalation (0.95)",
        "  +15.0 pts : chain_evidence = 1.0 (5 активных стадий атаки на хосте)",
        "  +14.3 pts : asset_criticality = 0.95 (целевой intranet-server)",
        "  +10.0 pts : attack_progression = 1.00 (эскалация после взлома веб-сервера)",
        "  +9.0 pts  : asset_vulnerability = 0.90 (EPSS / CVE-2020-24186)"
    ], ACCENT)

    # SLIDE 10: EXPERIMENTAL RESULTS ON ALL 8 SCENARIOS
    s10 = prs.slides.add_slide(blank)
    set_bg(s10)
    add_header(s10, "9. Экспериментальные результаты на всех 8 сценариях (2.60M алертов)", "Полное сравнение ESPM v0.2 с базовыми линиями Severity и RBA + Ablation Study", "Докладчик: Владимир")
    add_table_card(
        s10, 0.5, 1.3, 12.3, 4.2,
        ["Сценарий", "Split", "Алертов", "AUROC (ESPM/RBA/Sev)", "AP / PR-AUC (ESPM/RBA/Sev)", "P@10% (ESPM/RBA/Sev)", "Ранг Root PrivEsc (ESPM / RBA / Sev)"],
        [
            ["russellmitchell", "Design", "41 488", "0.952 / 0.945 / 0.720", "0.941 / 0.912 / 0.455", "100.0% / 95.6% / 13.5%", "#2.0 / #7 973 / #29 261"],
            ["shaw", "Design", "68 539", "0.933 / 0.929 / 0.718", "0.894 / 0.829 / 0.232", "75.9% / 75.9% / 5.4%", "#1.0 / #5 627 / #22 449"],
            ["wardbeck", "Design", "88 204", "0.935 / 0.928 / 0.689", "0.888 / 0.807 / 0.178", "59.8% / 59.4% / 4.4%", "#1.5 / #5 746 / #30 006"],
            ["santos", "Design", "126 513", "0.930 / 0.901 / 0.609", "0.862 / 0.687 / 0.143", "62.7% / 61.5% / 4.6%", "#1.0 / #9 745 / #52 053"],
            ["fox", "Design", "462 523", "0.998 / 0.993 / 0.796", "1.000 / 0.999 / 0.974", "100.0% / 99.4% / 75.9%", "#3.5 / #411 286 / #442 367"],
            ["wilson", "Design", "625 303", "0.995 / 0.984 / 0.692", "0.998 / 0.993 / 0.871", "100.0% / 96.6% / 49.0%", "#1.5 / #429 091 / #492 377"],
            ["harrison", "BLIND 1", "583 754", "0.995 / 0.973 / 0.622", "0.998 / 0.990 / 0.862", "100.0% / 94.1% / 50.9%", "#1.0 / #418 878 / #483 058"],
            ["wheeler", "BLIND 2", "603 939", "0.998 / 0.988 / 0.654", "0.999 / 0.995 / 0.864", "100.0% / 96.7% / 50.6%", "#310 (Top 0.05%) / #421k / #488k"],
            ["СРЕДНЕЕ (Macro)", "Все 8", "2 600 263", "0.967 / 0.955 / 0.688", "0.948 / 0.903 / 0.572", "87.3% / 84.9% / 31.8%", "Мед. #1.5 / #210 515 / #247 210"]
        ],
        col_widths=[1.7, 1.0, 1.2, 2.0, 2.1, 2.0, 2.3]
    )
    add_card(s10, 0.5, 5.62, 12.3, 1.45, "Выводы по Ablation Study и слепым тестам (harrison, wheeler)", [
        "1. На слепых сценариях harrison и wheeler (1.19M алертов) ESPM без перенастройки дал AUROC 0.995 и 0.998, Precision@10% = 100.0%.",
        "2. Отключение Asset Context ухудшает ранг захвата root с #1.5 до #6.3 (на shaw до #10); отключение Sequence Memory роняет ранг на russellmitchell/fox до #14–#17."
    ], ACCENT_GREEN)

    # SLIDE 11: VISUAL CHARTS (EMBEDDED FIGURES)
    s11_charts = prs.slides.add_slide(blank)
    set_bg(s11_charts)
    add_header(s11_charts, "10. Визуализация метрик ранжирования и объяснимости", "Графики AUROC/AP, рангов перехвата Root Escalation и декомпозиции вклада факторов", "Докладчики: Владимир и Сабыр")
    fig_dir = Path("04_prototype/espm/figures")
    if (fig_dir / "fig_auroc_ap.png").exists():
        s11_charts.shapes.add_picture(str(fig_dir / "fig_auroc_ap.png"), Inches(0.45), Inches(1.35), width=Inches(6.1))
    if (fig_dir / "fig_root_rank.png").exists():
        s11_charts.shapes.add_picture(str(fig_dir / "fig_root_rank.png"), Inches(6.75), Inches(1.35), width=Inches(6.1))
    if (fig_dir / "fig_explainability.png").exists():
        s11_charts.shapes.add_picture(str(fig_dir / "fig_explainability.png"), Inches(6.75), Inches(4.35), width=Inches(6.1))

    # SLIDE 12: EXPECTED FINAL RESULTS & 90+ PAPER
    s11 = prs.slides.add_slide(blank)
    set_bg(s11)
    add_header(s11, "11. Ожидаемые результаты, практическая ценность и статья (90+)", "План публикации и метрики успеха дипломного проекта", "Докладчик: Сабыр")
    add_card(s11, 0.5, 1.35, 6.0, 5.6, "Ожидаемые финальные результаты и ценность", [
        "Готовый open-source модуль ESPM v1.0 для Wazuh SIEM с коннектором реального времени и веб-дашбордом аналитика SOC.",
        "Кратное снижение нагрузки на аналитика (подавление >80% фонового шума в топ-очереди при медианном ранге #1.5 для захвата root-прав).",
        "Полная прозрачность каждого решения триажа (JSON + визуальная декомпозиция вкладов факторов без затрат на коммерческие LLM).",
        "Сравнение экспертных весов с автоматически откалиброванными весами (Constrained Logistic Regression на Design-сценариях)."
    ], ACCENT)
    add_card(s11, 6.7, 1.35, 6.1, 5.6, "План научной публикации (на оценку 90+)", [
        "Тема статьи: «ESPM: An Explainable Incident Prioritization Module for Open-Source SIEM Combining Asset Context and MITRE ATT&CK Event Sequence Analysis».",
        "Целевая площадка: конференция IEEE AITU Digital Generation / SIST / DTESI (или научный журнал университета), подача — январь–февраль 2027 г.",
        "Тип статьи: Полноценная исследовательская статья с собственной архитектурой и экспериментами на всех 8 сценариях (2.60 млн алертов AIT-ADS).",
        "Текущая готовность текста: В LaTeX-шаблоне AITU уже написаны и скомпилированы в PDF Введение, Главы 1–3, Заключение и Приложение."
    ], ACCENT_WARN)

    # SLIDE 13: TIMELINE & ROLES
    s12 = prs.slides.add_slide(blank)
    set_bg(s12)
    add_header(s12, "12. Таймлайн до финальной защиты и распределение ролей", "Согласованный календарный план работы команды (Сабыр и Владимир)", "Докладчик: Сабыр")
    add_table_card(
        s12, 0.5, 1.35, 12.3, 5.5,
        ["Этап и сроки", "Задачи Сабыра (Asset Context, Scoring, XAI, UI)", "Задачи Владимира (Wazuh Parser, Sequence, Eval, Docker)", "Итоговый артефакт этапа"],
        [
            ["1-я предзащита (Ноя–Дек 2026) ВЫПОЛНЕНО", "Литобзор (CAPE/EPSS/XAI), Location-Aware CMDB, ядро скоринга, JSON-объяснения, веб-дашборд dashboard.html, графики", "Литобзор (RBA/ATT&CK), парсер AIT-ADS, O(1) корзины последовательности, evaluate.py (все 8 сцен., 2.60M), 31 unit-тест", "Пакет 1-й предзащиты, PoC v0.2, скомпилированный PDF диплома в LaTeX"],
            ["Этап 2: Калибровка весов и Multi-IDS (Январь 2027)", "Модуль автоматической калибровки весов w_i ≥ 0 (LogReg / NNLS), оценка стабильности объяснений (Kendall's τ)", "Кросс-корреляция Wazuh с алертами Suricata (306k) и AMiner (55k) из AIT-ADS; адаптивный горизонт памяти цепочки", "ESPM v0.3, отчёт по обучению весов и мульти-сенсорной корреляции"],
            ["Этап 3: Live-стенд и Статья 90+ (Февраль 2027)", "Бэкенд REST API для дашборда SOC, экспорт отчётов; разделы Methodology & XAI научной статьи", "Docker-стенд Wazuh Manager + Agent, live-прогон атаки; разделы Experiments & Results статьи", "Docker-стенд Wazuh + поданная научная статья (90+)"],
            ["2-я предзащита (Фев–Март 2027)", "Демонстрация live UI-дашборда и сравнения экспертных и обученных весов", "Демонстрация потоковой интеграции с Wazuh в Docker и полных таблиц метрик", "Система ESPM v1.0, 85% текста диплома, статус статьи"],
            ["3-я предзащита и Финал (Апр–Июнь 2027)", "Оценка Faithfulness/Completeness объяснений, финальная вычитка Глав 1–2 и презентации ГЭК", "Нагрузочное тестирование (throughput/RAM), вычитка Главы 3 и Приложений", "100% готовый диплом в LaTeX, успешная защита ГЭК"]
        ],
        col_widths=[2.3, 3.8, 3.8, 2.4]
    )

    out_path = Path("05_predefense_package/PreDefense_1_Presentation_ESPM.pptx")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    prs.save(str(out_path))
    print(f"Presentation saved successfully to {out_path}")


if __name__ == "__main__":
    build()
