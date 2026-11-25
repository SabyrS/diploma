"""ESPM evaluation harness — AIT-ADS Wazuh alerts (v0.2, honest protocol).

For each scenario: stream alerts in time order through a FRESH ESPM scorer,
the severity baseline, the simplified RBA baseline and two ablations, join
attack-phase ground truth from labels.csv (EVALUATION ONLY) and report:

  * AUROC (rank-based, tie-corrected)
  * Average Precision (AP, area under precision-recall curve)
  * Precision@10% / Recall@10% of the queue
  * Root-escalation rank: best (= smallest) tie-averaged queue rank of a
    true privilege-escalation event (Wazuh groups 'sudo'/'su' inside the
    labelled reverse_shell / privilege_escalation windows)
  * Throughput of the ESPM scorer (alerts/second, single thread)

Usage:
    python evaluate.py --dataset-dir ../../03_dataset \
        --scenarios fox santos shaw wardbeck russellmitchell wilson harrison wheeler
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

from scoring import (Alert, ESPMScorer, parse_wazuh_jsonl,
                     baseline_severity, baseline_rba)

SCENARIOS = ["fox", "harrison", "russellmitchell", "santos",
             "shaw", "wardbeck", "wheeler", "wilson"]

# Split used in the thesis. 'design' scenarios were inspected while building
# the ATT&CK mapping and CMDB; 'blind' scenarios were never opened before the
# final evaluation run.
SPLIT = {
    "fox": "design", "santos": "design", "shaw": "design", "wardbeck": "design",
    "russellmitchell": "design", "wilson": "design",
    "harrison": "blind", "wheeler": "blind",
}

ABLATIONS = {
    "espm_no_asset": {"asset_criticality": 0.0, "asset_vulnerability": 0.0,
                      "asset_centrality": 0.0},
    "espm_no_sequence": {"attack_progression": 0.0, "chain_evidence": 0.0},
}


# ---------------- ground truth ---------------------------------------------

def load_labels(labels_csv: Path) -> dict[str, list]:
    """scenario -> [(attack, start, end)]"""
    out: dict[str, list] = defaultdict(list)
    with open(labels_csv, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out[row["scenario"]].append(
                (row["attack"], float(row["start"]), float(row["end"])))
    return dict(out)


def is_attack(alert: Alert, phases: list) -> bool:
    return any(s <= alert.ts <= e for (_n, s, e) in phases)


def is_root_escalation(alert: Alert, phases: list) -> bool:
    win = [p for p in phases if p[0] in ("reverse_shell", "privilege_escalation")]
    g = {x.lower() for x in alert.groups}
    return bool(g & {"sudo", "su"}) and is_attack(alert, win)


# ---------------- metrics ---------------------------------------------------

def _tie_ranks_desc(scores):
    """Average 1-based rank in a queue sorted by descending score."""
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def auroc(scores, labels) -> float:
    """Rank-based (Mann-Whitney U) AUROC with tie correction."""
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return float("nan")
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    rank_sum_pos = 0.0
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg_rank = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            if labels[order[k]] == 1:
                rank_sum_pos += avg_rank
        i = j + 1
    return (rank_sum_pos - n_pos * (n_pos + 1) / 2.0) / (n_pos * n_neg)


def average_precision(scores, labels) -> float:
    """AP with ties treated as one block (step-wise PR curve)."""
    n_pos = sum(labels)
    if n_pos == 0:
        return float("nan")
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    ap, tp, seen, i = 0.0, 0, 0, 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        block = order[i:j + 1]
        block_tp = sum(labels[k] for k in block)
        tp += block_tp
        seen += len(block)
        ap += (block_tp / n_pos) * (tp / seen)
        i = j + 1
    return ap


def precision_at_k(scores, labels, k_frac=0.10) -> float:
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    k = max(1, int(len(order) * k_frac))
    return sum(labels[i] for i in order[:k]) / k


def recall_at_k(scores, labels, k_frac=0.10) -> float:
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    k = max(1, int(len(order) * k_frac))
    n_pos = sum(labels) or 1
    return sum(labels[i] for i in order[:k]) / n_pos


def metric_block(scores, labels, root_idx):
    ranks = _tie_ranks_desc(scores) if root_idx else None
    best = min(ranks[i] for i in root_idx) if root_idx else None
    return {
        "auroc": round(auroc(scores, labels), 4),
        "ap": round(average_precision(scores, labels), 4),
        "precision@10%": round(precision_at_k(scores, labels), 4),
        "recall@10%": round(recall_at_k(scores, labels), 4),
        "root_escalation_best_rank": None if best is None else round(best, 1),
    }


# ---------------- runner ----------------------------------------------------

def run_scenario(path: Path, phases: list) -> dict:
    t0 = time.time()
    alerts = [a for a in parse_wazuh_jsonl(path) if a.ts > 0]
    alerts.sort(key=lambda a: a.ts)            # chronological replay
    t_parse = time.time() - t0

    labels = [1 if is_attack(a, phases) else 0 for a in alerts]
    root_idx = [i for i, a in enumerate(alerts) if is_root_escalation(a, phases)]

    scores = {}
    scorer = ESPMScorer()                      # fresh state per scenario
    t1 = time.time()
    scores["espm"] = [scorer.score(a).priority for a in alerts]
    t_score = time.time() - t1
    for name, w in ABLATIONS.items():
        sc = ESPMScorer(weights=w)
        scores[name] = [sc.score(a).priority for a in alerts]
    scores["severity_baseline"] = [baseline_severity(a) for a in alerts]
    scores["rba_baseline"] = [baseline_rba(a) for a in alerts]

    n = len(alerts)
    rep = {
        "split": SPLIT.get(path.stem.replace("_wazuh", ""), "?"),
        "n_alerts": n,
        "n_attack_alerts": sum(labels),
        "attack_frac": round(sum(labels) / max(1, n), 4),
        "n_root_escalation_events": len(root_idx),
        "parse_seconds": round(t_parse, 1),
        "espm_alerts_per_second": round(n / max(t_score, 1e-9)),
    }
    for name, s in scores.items():
        rep[name] = metric_block(s, labels, root_idx)
    return rep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-dir", default="../../03_dataset")
    ap.add_argument("--scenarios", nargs="+", default=SCENARIOS)
    ap.add_argument("--out", default="results.json")
    args = ap.parse_args()

    ddir = Path(args.dataset_dir)
    labels_all = load_labels(ddir / "labels.csv")
    report = {}
    for sc in args.scenarios:
        path = ddir / f"{sc}_wazuh.json"
        if not path.exists():
            print(f"[!] {path} not found — extract it from ait_ads.zip first",
                  file=sys.stderr)
            continue
        r = run_scenario(path, labels_all[sc])
        report[sc] = r
        print(f"\n=== {sc} [{r['split']}] alerts={r['n_alerts']} "
              f"attack={r['attack_frac']*100:.1f}% root_events={r['n_root_escalation_events']} "
              f"espm_speed={r['espm_alerts_per_second']}/s", flush=True)
        for key in ("espm", "espm_no_asset", "espm_no_sequence",
                    "rba_baseline", "severity_baseline"):
            m = r[key]
            print(f"  {key:18s} AUROC={m['auroc']:.3f} AP={m['ap']:.3f} "
                  f"P@10%={m['precision@10%']:.3f} R@10%={m['recall@10%']:.3f} "
                  f"root_rank={m['root_escalation_best_rank']}", flush=True)
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n[saved] {args.out}")


if __name__ == "__main__":
    main()
