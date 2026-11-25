"""Run evaluation on scenarios, writing results incrementally to eval_progress.txt
so partial output survives interruption."""
import sys, time
sys.path.insert(0, '.')

from pathlib import Path
from scoring import ESPMScorer, parse_wazuh_jsonl, baseline_severity, baseline_rba
from evaluate import load_labels, is_attack, auroc, precision_at_k, recall_at_k

scenarios = sys.argv[1:] or ['fox', 'wilson', 'russellmitchell']
lab = load_labels(Path('../../03_dataset/labels.csv'))
out = open('eval_progress.txt', 'w', encoding='utf-8', buffering=1)

for sc in scenarios:
    t0 = time.time()
    p = Path(f'../../03_dataset/{sc}_wazuh.json')
    alerts = [a for a in parse_wazuh_jsonl(p) if a.ts > 0]
    alerts.sort(key=lambda a: a.ts)
    out.write(f'== {sc}: parsed {len(alerts)} alerts in {time.time()-t0:.0f}s\n')
    scorer = ESPMScorer()
    espm, sev, rba, labels = [], [], [], []
    for i, a in enumerate(alerts):
        s = scorer.score(a)
        espm.append(s.priority); sev.append(baseline_severity(a)); rba.append(baseline_rba(a))
        labels.append(1 if is_attack(a, lab[sc]) else 0)
    out.write(f'== {sc}: alerts={len(labels)} attack={sum(labels)} ({sum(labels)/len(labels)*100:.1f}%)\n')
    for name, arr in (('ESPM', espm), ('severity', sev), ('RBA', rba)):
        out.write(f'  {name:9s} AUROC={auroc(arr, labels):.3f} P@10%={precision_at_k(arr, labels):.3f} R@10%={recall_at_k(arr, labels):.3f}\n')
out.write('DONE\n')
out.close()
print('finished')
