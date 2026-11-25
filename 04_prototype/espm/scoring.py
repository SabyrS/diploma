"""ESPM — Explainable Security incident Prioritization Module (PoC v0.2).

Pipeline:
  Wazuh alerts (AIT-ADS) -> Normalization -> Asset Context Enrichment ->
  Event Sequence Analysis (MITRE ATT&CK + Time-Bucketed Burst & Kill-Chain Memory) ->
  Additive Scoring -> Machine-Readable & Human-Readable Explanation JSON.

Labels come from labels.csv (attack phase ground truth) and are used
EVALUATION-ONLY: no label information enters the scoring factors.

Authors & Module Ownership:
  - Sabyr: Asset Context Enrichment (CMDB schema, EPSS/criticality/centrality modeling),
           Additive Explainable Scoring Engine, Explanation Renderer & Web Dashboard.
  - Vladimir: Wazuh JSONL Ingestion & Normalization, MITRE ATT&CK v20 Phase Mapping,
              Time-Bucketed Event Sequence Analysis, Evaluation Harness & Baselines.
"""
from __future__ import annotations

import collections
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

# --------------------------------------------------------------------------
# 1. Normalization
# --------------------------------------------------------------------------

@dataclass
class Alert:
    ts: float                 # unix epoch
    host: str                 # agent hostname (asset key)
    agent_ip: str
    rule_id: str
    level: int                # wazuh severity 0..15
    groups: list
    description: str
    full_log: str
    location: str

def parse_wazuh_jsonl(path: str | Path) -> Iterator[Alert]:
    """Stream-parse a Wazuh alerts JSONL file (one JSON object per line)."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            rule = obj.get("rule", {})
            agent = obj.get("agent", {})
            pre = obj.get("predecoder", {})
            ts = obj.get("@timestamp") or ""
            try:
                epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            except ValueError:
                epoch = 0.0
            yield Alert(
                ts=epoch,
                host=pre.get("hostname") or agent.get("name") or "unknown",
                agent_ip=agent.get("ip", ""),
                rule_id=str(rule.get("id", "")),
                level=int(rule.get("level", 0) or 0),
                groups=list(rule.get("groups", [])),
                description=rule.get("description", ""),
                full_log=obj.get("full_log", "")[:500],
                location=obj.get("location", ""),
            )

# --------------------------------------------------------------------------
# 2. Asset Context (CMDB over AIT-ADS testbed hosts & log locations)
# --------------------------------------------------------------------------

@dataclass
class Asset:
    criticality: float   # business criticality 0..1
    vulnerability: float # worst EPSS-style exploitability 0..1
    centrality: float    # network centrality 0..1
    role: str

HOST_PATTERNS = [
    # (regex, role, criticality, vulnerability, centrality)
    (r"^mail$",                "mail-server",        0.9,  0.6,  0.8),
    (r"-mail$",                "mail-server",        0.8,  0.7,  0.7),
    (r"^webserver$",           "web-server",         0.8,  0.7,  0.7),
    (r"^intranet",             "intranet-server",    0.95, 0.90, 0.85),
    (r"^cloud",                "cloud",              0.6,  0.5,  0.5),
    (r"^(proxy|gateway)",      "gateway",            0.7,  0.4,  0.9),
    (r"ubuntu\.com|launchpad", "external",           0.1,  0.0,  0.2),
    (r"hugedomains|kayak",     "external",           0.1,  0.0,  0.2),
    (r"mailserver",            "mail-server",        0.8,  0.7,  0.7),
]

def classify_asset(host: str, location: str = "") -> Asset:
    """Resolve asset context from hostname and (when available) log location.

    In AIT-ADS, Apache intranet logs and Suricata logs collected without syslog
    headers carry agent.name='wazuh-client' while 'location' identifies the
    actual service (/var/log/apache2/intranet-access.log vs /var/log/suricata/*).
    """
    loc = (location or "").lower()
    h = (host or "").lower()
    if loc:
        if "apache2/intranet" in loc or "apache2/access" in loc or "apache2/error" in loc or "/audit/" in loc:
            return Asset(criticality=0.95, vulnerability=0.90, centrality=0.85, role="intranet-server")
        if "suricata" in loc:
            return Asset(criticality=0.35, vulnerability=0.20, centrality=0.50, role="network-ids-sensor")
        if "mail." in loc or "/mail" in loc:
            return Asset(criticality=0.55, vulnerability=0.30, centrality=0.50, role="mail-server")

    for pat, role, crit, vuln, cent in HOST_PATTERNS:
        if re.search(pat, host, re.I):
            if role == "intranet-server" and not loc:
                return Asset(criticality=0.7, vulnerability=0.5, centrality=0.6, role="intranet")
            return Asset(criticality=crit, vulnerability=vuln, centrality=cent, role=role)
    return Asset(criticality=0.3, vulnerability=0.3, centrality=0.3, role="client")

# --------------------------------------------------------------------------
# 3. Event Sequence Analysis (ATT&CK-phase mapping from rule groups)
# --------------------------------------------------------------------------

PHASE_BY_GROUP = [
    # (matched group/desc token, stage, ATT&CK tactic, phase_score)
    (("sudo", "su", "audit"),             "privilege_escalation", "Privilege Escalation", 0.95),
    (("attack", "appsec", "webshell"),    "web_attack",           "Initial Access",       0.80),
    (("access_denied",),                  "suspicious",           "Defense Evasion",      0.75),
    (("web_scan", "recon", "nmap"),       "network_scans",        "Reconnaissance",       0.65),
    (("wpscan", "dirb"),                  "service_scans",        "Reconnaissance",       0.65),
    (("invalid_login", "authentication_failed",
      "authentication_failures"),         "cracking",             "Credential Access",    0.60),
    (("authentication_success",),         "access_gain",          "Execution",            0.65),
    (("fts",),                            "first_time_seen",      "Execution",            0.55),
    (("accesslog", "system_error"),       "error",                "—",                    0.35),
    (("ids", "suricata"),                 "ids_signal",           "Discovery",            0.12),
    (("virus", "clamd", "freshclam"),     "av_update",            "—",                    0.05),
]

DEFAULT_PHASE = ("other", "—", 0.25)

def attack_phase(alert: Alert):
    """Map a Wazuh alert to a kill-chain stage via rule groups/description."""
    gset = {g.lower() for g in alert.groups}
    blob = " ".join(alert.groups).lower() + " " + alert.description.lower()
    # Routine Dovecot IMAP polling (rule 9701, level 3) is benign background activity
    if "dovecot" in blob and "authentication_success" in blob and alert.level <= 3:
        return ("routine_auth", "—", 0.05)
    # Privilege escalation via sudo / su / auditd
    if gset & {"sudo", "su", "audit"}:
        return ("privilege_escalation", "Privilege Escalation", 0.95)
    # PAM session opened on critical intranet server after web compromise
    if "pam" in gset and "intranet" in alert.host.lower():
        return ("access_gain", "Execution", 0.85)
    for tokens, stage, tactic, score in PHASE_BY_GROUP:
        if stage == "privilege_escalation":
            continue
        if any(t in blob for t in tokens):
            return stage, tactic, score
    return DEFAULT_PHASE

# --------------------------------------------------------------------------
# 4. Scoring engine — additive, weights in YAML-serializable config
# --------------------------------------------------------------------------

DEFAULT_WEIGHTS = {
    "severity":               0.15,   # group C: raw Wazuh severity baseline
    "asset_criticality":      0.15,   # group A: business criticality (CMDB)
    "asset_vulnerability":    0.10,   # group A: max EPSS / CVE exposure
    "asset_centrality":       0.05,   # group A: network topology centrality
    "attack_phase":           0.30,   # group B: MITRE ATT&CK kill-chain position
    "attack_progression":     0.10,   # group B: temporal burst rate vs baseline
    "chain_evidence":         0.15,   # group B: multi-stage kill-chain correlation
}

@dataclass
class ScoredAlert:
    alert: Alert
    priority: float
    factors: dict           # factor -> value in [0, 1]
    explanation: list       # sorted [{factor, value, contribution, why}]
    stage: str
    tactic: str

class ESPMScorer:
    """O(1) amortized streaming scorer with 1-second time buckets and kill-chain memory."""

    def __init__(self, weights: dict | None = None, window_s: float = 600.0,
                 chain_window_s: float = 3600.0):
        self.w = dict(DEFAULT_WEIGHTS)
        if weights:
            self.w.update(weights)
        self.window_s = window_s
        self.chain_window_s = chain_window_s
        # asset_key -> deque of [sec_bucket, count, max_phase_score] (max 600 items)
        self._host_buckets: dict[str, collections.deque] = {}
        # asset_key -> running sum of alerts in current window
        self._window_counts: collections.Counter = collections.Counter()
        # asset_key -> {stage: (last_ts, phase_score)} for O(1) multi-stage memory
        self._stage_memory: dict[str, dict[str, tuple[float, float]]] = {}
        # asset_key -> (cumulative_count, first_ts)
        self._host_count: dict[str, tuple[int, float]] = {}

    def score(self, alert: Alert) -> ScoredAlert:
        asset = classify_asset(alert.host, alert.location)
        stage, tactic, phase_score = attack_phase(alert)

        # Canonical key links logs from the same logical server
        hkey = asset.role if asset.role in ("intranet-server", "network-ids-sensor") else alert.host
        sec = int(alert.ts)

        # --- 1. Sliding window burst tracking (O(1) via 1-second buckets) ---
        dq = self._host_buckets.setdefault(hkey, collections.deque())
        cutoff = sec - int(self.window_s)
        while dq and dq[0][0] < cutoff:
            old_sec, old_cnt, _ = dq.popleft()
            self._window_counts[hkey] = max(0, self._window_counts[hkey] - old_cnt)

        prior_window_count = self._window_counts[hkey]
        max_recent_phase = max((m for (_, _, m) in dq), default=0.0)

        if dq and dq[-1][0] == sec:
            dq[-1][1] += 1
            if phase_score > dq[-1][2]:
                dq[-1][2] = phase_score
        else:
            dq.append([sec, 1, phase_score])
        self._window_counts[hkey] += 1

        # --- 2. Multi-stage kill-chain memory (O(1) stage dict) ---
        smem = self._stage_memory.setdefault(hkey, {})
        expired = [st for st, (t_last, _) in smem.items() if alert.ts - t_last > self.chain_window_s]
        for st in expired:
            del smem[st]

        has_higher_recent = max_recent_phase > phase_score + 0.1
        active_attack_stages = sum(1 for st, (_, ps) in smem.items() if ps >= 0.60 and st != stage)

        if has_higher_recent or (active_attack_stages >= 1 and phase_score >= 0.65):
            chain = 1.0
        elif prior_window_count > 0:
            chain = 0.6
        else:
            chain = 0.0

        smem[stage] = (alert.ts, phase_score)

        # --- 3. Attack progression (short-term rate vs long-run baseline) ---
        cnt = self._host_count.get(hkey, (0, alert.ts))
        n_total, t_first = cnt[0] + 1, cnt[1]
        self._host_count[hkey] = (n_total, t_first)
        long_rate = n_total / max(alert.ts - t_first, self.window_s)
        short_rate = prior_window_count / self.window_s if prior_window_count else 0.0
        progression = min(1.0, short_rate / (2.0 * max(long_rate, 1.0 / 3600.0)))
        if active_attack_stages >= 1 and phase_score >= 0.85:
            progression = max(progression, min(1.0, 0.50 + 0.25 * active_attack_stages))

        f_severity = min(1.0, alert.level / 15.0)

        factors = {
            "severity":             f_severity,
            "asset_criticality":    asset.criticality,
            "asset_vulnerability":  asset.vulnerability,
            "asset_centrality":     asset.centrality,
            "attack_phase":         phase_score,
            "attack_progression":   progression,
            "chain_evidence":       chain,
        }
        contrib = {k: self.w[k] * v for k, v in factors.items()}
        w_sum = sum(self.w.values()) or 1.0
        priority = 100.0 * min(1.0, sum(contrib.values()) / w_sum)

        why = {
            "severity":            f"wazuh rule.level={alert.level} ({f_severity:.2f})",
            "asset_criticality":   f"asset '{hkey}' role={asset.role} (crit={asset.criticality})",
            "asset_vulnerability": f"EPSS/CVE exposure score={asset.vulnerability}",
            "asset_centrality":    f"network topology centrality={asset.centrality}",
            "attack_phase":        f"stage={stage} MITRE tactic={tactic}",
            "attack_progression":  f"{prior_window_count} alerts in {int(self.window_s)}s window vs baseline",
            "chain_evidence":      f"prior_alerts={prior_window_count}, active_killchain_stages={active_attack_stages + 1}",
        }
        explanation = [
            {"factor": k, "value": round(factors[k], 3),
             "contribution": round(contrib[k], 4), "why": why[k]}
            for k in sorted(contrib, key=contrib.get, reverse=True)
        ]
        return ScoredAlert(alert=alert, priority=round(priority, 2),
                           factors=factors, explanation=explanation,
                           stage=stage, tactic=tactic)

# --------------------------------------------------------------------------
# 5. Baselines for comparison
# --------------------------------------------------------------------------

def baseline_severity(alert: Alert) -> float:
    return alert.level / 15.0 * 100.0

def baseline_rba(alert: Alert) -> float:
    """Simplified RBA: severity + asset risk bump (contextual baseline without sequence)."""
    a = classify_asset(alert.host, alert.location)
    return 100.0 * min(1.0, (0.7 * min(1.0, alert.level / 15.0)
                             + 0.3 * (a.criticality + a.vulnerability) / 2))
