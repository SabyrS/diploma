"""ESPM unit tests — run with: python test_espm.py (no pytest needed).

Hand-computed expectations for scoring math, phase mapping, asset
classification (including location-aware CMDB enrichment), multi-stage
kill-chain correlation, parser robustness, and explanation integrity.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from scoring import (Alert, ESPMScorer, attack_phase, classify_asset,
                     parse_wazuh_jsonl, DEFAULT_WEIGHTS, baseline_rba,
                     baseline_severity)

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name}")


# ---------- asset classification ------------------------------------------
a = classify_asset("mail")
check("mail -> criticality 0.9", a.criticality == 0.9)
check("mail -> role mail-server", a.role == "mail-server")
a = classify_asset("davey-mail")
check("*-mail -> role mail-server", a.role == "mail-server")
a = classify_asset("archive.ubuntu.com")
check("external -> criticality 0.1", a.criticality == 0.1)
a = classify_asset("unknown-laptop-42")
check("unknown host -> defaults 0.3", a.criticality == 0.3 and a.role == "client")
a = classify_asset("proxy.price.fox.org")
check("proxy -> centrality 0.9", a.centrality == 0.9)

# v0.2 location-aware asset classification
a_web = classify_asset("wazuh-client", "/var/log/apache2/intranet-access.log")
check("apache2/intranet-access.log -> intranet-server (crit=0.95)",
      a_web.role == "intranet-server" and a_web.criticality == 0.95)
a_ids = classify_asset("wazuh-client", "/var/log/suricata/eve.json")
check("suricata/eve.json -> network-ids-sensor (crit=0.35)",
      a_ids.role == "network-ids-sensor" and a_ids.criticality == 0.35)

# ---------- phase mapping ---------------------------------------------------
al = Alert(ts=1.0, host="h", agent_ip="1.2.3.4", rule_id="1", level=5,
           groups=["web", "accesslog", "attack"], description="x",
           full_log="", location="")
check("'attack' group -> web_attack/Initial Access",
      attack_phase(al)[0] == "web_attack")
al.groups = ["web", "accesslog", "web_scan"]
check("'web_scan' -> network_scans", attack_phase(al)[0] == "network_scans")
al.groups = ["syslog", "sshd", "recon"]
check("'recon' -> network_scans", attack_phase(al)[0] == "network_scans")
al.groups = ["dovecot", "invalid_login"]
check("'invalid_login' -> cracking", attack_phase(al)[0] == "cracking")
al.groups = ["whatever", "unmatched"]
check("unmatched -> default other", attack_phase(al)[0] == "other")

# v0.2 routine dovecot vs privilege escalation
al_dove = Alert(ts=1.0, host="mail", agent_ip="1.2.3.4", rule_id="9701", level=3,
                groups=["dovecot", "authentication_success"],
                description="Dovecot Authentication Success.", full_log="", location="/var/log/mail.log")
check("dovecot level 3 -> routine_auth (0.05)",
      attack_phase(al_dove)[0] == "routine_auth" and attack_phase(al_dove)[2] == 0.05)

al_sudo = Alert(ts=2.0, host="intranet-server", agent_ip="1.2.3.4", rule_id="5402", level=3,
                groups=["syslog", "sudo"],
                description="Successful sudo to ROOT executed.", full_log="", location="/var/log/auth.log")
check("sudo to ROOT -> privilege_escalation (0.95)",
      attack_phase(al_sudo)[0] == "privilege_escalation" and attack_phase(al_sudo)[2] == 0.95)

# ---------- scoring math ----------------------------------------------------
sc = ESPMScorer()
s = sc.score(al)  # al currently 'other' phase, level 5
check("priority in [0,100]", 0 <= s.priority <= 100)
wsum = sum(DEFAULT_WEIGHTS.values())
manual = 100.0 * min(1.0, sum(DEFAULT_WEIGHTS[k] * v
                              for k, v in s.factors.items()) / wsum)
check("priority matches hand-computed sum", abs(s.priority - manual) < 0.05)
check("explanation factors == 7", len(s.explanation) == 7)
check("explanation sorted desc by contribution",
      all(s.explanation[i]["contribution"] >= s.explanation[i + 1]["contribution"]
          for i in range(6)))
check("contributions sum == weighted factor sum (rounding 4dp)",
      abs(sum(e["contribution"] for e in s.explanation)
          - sum(DEFAULT_WEIGHTS[k] * v for k, v in s.factors.items())) < 1e-3)

# severity factor uses level/15
al2 = Alert(ts=2.0, host="h", agent_ip="", rule_id="2", level=15,
            groups=["x"], description="", full_log="", location="")
s2 = sc.score(al2)
check("level 15 -> severity factor 1.0", s2.factors["severity"] == 1.0)
al3 = Alert(ts=3.0, host="h", agent_ip="", rule_id="3", level=0,
            groups=["x"], description="", full_log="", location="")
s3 = sc.score(al3)
check("level 0 -> severity factor 0.0", s3.factors["severity"] == 0.0)

# chain evidence: later stage in history boosts factor
sc2 = ESPMScorer()
early = Alert(ts=1.0, host="web", agent_ip="", rule_id="r", level=5,
              groups=["web_scan"], description="", full_log="", location="")
late = Alert(ts=60.0, host="web", agent_ip="", rule_id="r", level=5,
             groups=["web", "accesslog", "attack"], description="",
             full_log="", location="")
sc2.score(late)                       # plant a late-stage alert in history
again = Alert(ts=120.0, host="web", agent_ip="", rule_id="r", level=5,
              groups=["web_scan"], description="", full_log="", location="")
sa = sc2.score(again)
check("chain_evidence=1 when later stage precedes",
      sa.factors["chain_evidence"] == 1.0)

# multi-stage kill chain: web_attack followed by low-level sudo on intranet-server
sc3 = ESPMScorer()
sc3.score(Alert(ts=100.0, host="wazuh-client", agent_ip="", rule_id="31101", level=5,
                groups=["web", "accesslog", "attack"], description="Web server 400 error code.",
                full_log="", location="/var/log/apache2/intranet-access.log"))
s_privesc = sc3.score(Alert(ts=500.0, host="intranet-server", agent_ip="", rule_id="5402", level=3,
                            groups=["syslog", "sudo"], description="Successful sudo to ROOT executed.",
                            full_log="", location="/var/log/auth.log"))
check("low-level (level=3) sudo on compromised intranet-server gets priority > 75",
      s_privesc.priority > 75.0 and baseline_severity(s_privesc.alert) == 20.0)

# ---------- baselines -------------------------------------------------------
check("severity baseline scales level", baseline_severity(al3) == 0.0
      and abs(baseline_severity(al2) - 100.0) < 1e-9)
rb = baseline_rba(al)
check("rba baseline in [0,100]", 0 <= rb <= 100)

# ---------- parser robustness ----------------------------------------------
with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                 encoding="utf-8") as fh:
    fh.write(json.dumps({
        "predecoder": {"hostname": "mail", "timestamp": "Jan 15 02:32:32"},
        "agent": {"ip": "10.0.0.1", "name": "ag"},
        "rule": {"id": "27", "level": 5, "description": "d",
                 "groups": ["g1", "g2"]},
        "full_log": "log line", "@timestamp": "2022-01-15T02:32:32.000000Z",
        "location": "/var/log/x"}) + "\n")
    fh.write("not json at all\n")                      # corrupt line: skip
    fh.write("")                                        # empty line: skip
    fh.write(json.dumps({"rule": {"id": "1"}}) + "\n")  # minimal: defaults
    tf = fh.name
parsed = list(parse_wazuh_jsonl(tf))
check("parser survives corrupt lines", len(parsed) == 2)
check("parsed host taken from predecoder", parsed[0].host == "mail")
check("parsed level 5", parsed[0].level == 5)
check("parsed ts epoch", abs(parsed[0].ts - 1642213952.0) < 1.0)
check("minimal alert defaults level 0", parsed[1].level == 0)
Path(tf).unlink()

print(f"\n{PASS} passed, {FAIL} failed")
raise SystemExit(1 if FAIL else 0)
