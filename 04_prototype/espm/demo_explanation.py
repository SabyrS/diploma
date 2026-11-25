"""Demo: print a prioritized queue sample with explanations for one scenario."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scoring import ESPMScorer, parse_wazuh_jsonl
from evaluate import load_labels, is_attack


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-dir", default="../../03_dataset")
    ap.add_argument("--scenario", default="russellmitchell")
    ap.add_argument("--top", type=int, default=5)
    args = ap.parse_args()

    ddir = Path(args.dataset_dir)
    phases = load_labels(ddir / "labels.csv").get(args.scenario, [])
    alerts = [a for a in parse_wazuh_jsonl(ddir / f"{args.scenario}_wazuh.json")
              if a.ts > 0]
    alerts.sort(key=lambda a: a.ts)

    scorer = ESPMScorer()
    scored = []
    for a in alerts:
        s = scorer.score(a)
        truth = "ATTACK" if is_attack(a, phases) else "normal"
        scored.append((s, truth))

    scored.sort(key=lambda p: p[0].priority, reverse=True)

    print(f"ESPM prioritized queue — top {args.top} of {len(scored)} alerts "
          f"(scenario={args.scenario})\n" + "=" * 78)
    for s, truth in scored[:args.top]:
        a = s.alert
        print(f"\npriority={s.priority:.1f}  [{truth}]  stage={s.stage}  "
              f"tactic={s.tactic}")
        print(f"  alert: host={a.host} rule={a.rule_id} level={a.level} "
              f"groups={','.join(a.groups[:3])}")
        print(f"  log:   {a.full_log[:90]}")
        print("  why (factors by contribution):")
        for e in s.explanation[:4]:
            print(f"    +{e['contribution']:.3f}  {e['factor']:<20} {e['why']}")

    # also dump one full machine-readable explanation
    top_json = {
        "priority": scored[0][0].priority,
        "alert": {
            "ts": scored[0][0].alert.ts, "host": scored[0][0].alert.host,
            "rule_id": scored[0][0].alert.rule_id,
            "level": scored[0][0].alert.level,
            "groups": scored[0][0].alert.groups,
        },
        "stage": scored[0][0].stage,
        "tactic": scored[0][0].tactic,
        "ground_truth": scored[0][1],
        "explanation": scored[0][0].explanation,
    }
    out = Path("explanation_example.json")
    out.write_text(json.dumps(top_json, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\n[saved] {out} — machine-readable explanation of the top alert")


if __name__ == "__main__":
    main()
