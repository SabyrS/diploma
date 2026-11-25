"""Generate publication-quality figures for the LaTeX thesis and Pre-Defense presentation."""
import json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.sans-serif"] = "DejaVu Sans"
plt.rcParams["axes.edgecolor"] = "#334155"
plt.rcParams["axes.linewidth"] = 0.8

res_path = Path("04_prototype/espm/results.json")
data = json.loads(res_path.read_text(encoding="utf-8"))

scenarios = ["russellmitchell", "shaw", "wardbeck", "santos", "fox", "wilson", "harrison", "wheeler"]
labels_sc = ["russell-\nmitchell", "shaw", "wardbeck", "santos", "fox", "wilson", "harrison\n(blind)", "wheeler\n(blind)"]

out_dirs = [
    Path("04_prototype/espm/figures"),
    Path("thesis_template/AITU_Diploma_2025-2026/chapters/chapter02/fig02"),
]
for d in out_dirs:
    d.mkdir(parents=True, exist_ok=True)

def save_all(fig, name):
    for d in out_dirs:
        fig.savefig(d / name, dpi=220, bbox_inches="tight")
    plt.close(fig)

# -------------------------------------------------------------------------
# Figure 1: AUROC and Average Precision (AP) across all 8 scenarios
# -------------------------------------------------------------------------
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 6.8), sharex=True)
x = np.arange(len(scenarios))
w = 0.26

espm_auroc = [data[s]["espm"]["auroc"] for s in scenarios]
rba_auroc  = [data[s]["rba_baseline"]["auroc"] for s in scenarios]
sev_auroc  = [data[s]["severity_baseline"]["auroc"] for s in scenarios]

ax1.bar(x - w, espm_auroc, w, label="ESPM v0.2 (Proposed)", color="#0284c7", edgecolor="#0369a1")
ax1.bar(x,     rba_auroc,  w, label="RBA Baseline (Context Only)", color="#eab308", edgecolor="#ca8a04")
ax1.bar(x + w, sev_auroc,  w, label="Severity Baseline (Wazuh rule.level)", color="#ef4444", edgecolor="#b91c1c")
ax1.set_ylabel("AUROC", fontsize=11, fontweight="bold")
ax1.set_ylim(0.50, 1.05)
ax1.set_title("Comparison of Incident Prioritization Performance Across All 8 AIT-ADS Scenarios (2,600,263 Alerts)", fontsize=12, fontweight="bold", pad=10)
ax1.grid(axis="y", linestyle="--", alpha=0.4)
ax1.legend(loc="lower right", frameon=True, fontsize=9.5)

espm_ap = [data[s]["espm"]["ap"] for s in scenarios]
rba_ap  = [data[s]["rba_baseline"]["ap"] for s in scenarios]
sev_ap  = [data[s]["severity_baseline"]["ap"] for s in scenarios]

ax2.bar(x - w, espm_ap, w, label="ESPM v0.2 (Macro AP = 0.948)", color="#0284c7", edgecolor="#0369a1")
ax2.bar(x,     rba_ap,  w, label="RBA Baseline (Macro AP = 0.903)", color="#eab308", edgecolor="#ca8a04")
ax2.bar(x + w, sev_ap,  w, label="Severity Baseline (Macro AP = 0.572)", color="#ef4444", edgecolor="#b91c1c")
ax2.set_ylabel("Average Precision (PR-AUC)", fontsize=11, fontweight="bold")
ax2.set_ylim(0.0, 1.08)
ax2.set_xticks(x)
ax2.set_xticklabels(labels_sc, fontsize=9.5)
ax2.grid(axis="y", linestyle="--", alpha=0.4)
ax2.legend(loc="lower right", frameon=True, fontsize=9.5)

plt.tight_layout()
save_all(fig, "fig_auroc_ap.png")

# -------------------------------------------------------------------------
# Figure 2: Root Privilege Escalation Best Queue Rank (Log Scale)
# -------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(10, 4.4))
espm_rk = [data[s]["espm"]["root_escalation_best_rank"] for s in scenarios]
rba_rk  = [data[s]["rba_baseline"]["root_escalation_best_rank"] for s in scenarios]
sev_rk  = [data[s]["severity_baseline"]["root_escalation_best_rank"] for s in scenarios]

b1 = ax.bar(x - w, espm_rk, w, label="ESPM v0.2 (Median Rank #1.5)", color="#16a34a", edgecolor="#15803d")
b2 = ax.bar(x,     rba_rk,  w, label="RBA Baseline (Median Rank #210,515)", color="#eab308", edgecolor="#ca8a04")
b3 = ax.bar(x + w, sev_rk,  w, label="Severity Baseline (Median Rank #247,210)", color="#ef4444", edgecolor="#b91c1c")

ax.set_yscale("log")
ax.set_ylim(0.7, 1500000)
ax.set_ylabel("Best Queue Rank of Root Escalation (log scale)\n[Lower = Better, #1 = Top of SOC Queue]", fontsize=10, fontweight="bold")
ax.set_title("Queue Rank of Root Privilege Escalation Events (su / sudo to ROOT, Wazuh level=3)", fontsize=11.5, fontweight="bold", pad=10)
ax.set_xticks(x)
ax.set_xticklabels(labels_sc, fontsize=9.5)
ax.grid(axis="y", linestyle="--", alpha=0.4)
ax.legend(loc="upper left", frameon=True, fontsize=9.5)

for rect, val in zip(b1, espm_rk):
    ax.text(rect.get_x() + rect.get_width()/2.0, val * 1.25, f"#{val:g}", ha="center", va="bottom", fontsize=8.5, fontweight="bold", color="#15803d")

plt.tight_layout()
save_all(fig, "fig_root_rank.png")

# -------------------------------------------------------------------------
# Figure 3: Explainability by Design — Factor Attribution Decomposition
# -------------------------------------------------------------------------
fig, (axL, axR) = plt.subplots(1, 2, figsize=(11, 4.2), sharex=True)

factors_names = [
    "attack_phase (MITRE)",
    "chain_evidence (3600s)",
    "asset_criticality (CMDB)",
    "attack_progression (600s)",
    "asset_vulnerability (EPSS)",
    "asset_centrality",
    "severity (Wazuh rule.level)"
]
y = np.arange(len(factors_names))

# Left: True Root Privilege Escalation (Rule 5402 sudo to ROOT, level=3 -> ESPM 84.0)
c_true = [28.5, 15.0, 14.25, 10.0, 9.0, 4.25, 3.0]
axL.barh(y, c_true, color="#0284c7", edgecolor="#0369a1")
axL.set_yticks(y)
axL.set_yticklabels(factors_names, fontsize=9.5)
axL.invert_yaxis()
axL.set_xlabel("Contribution to Priority Score (points out of 100)", fontsize=9.5)
axL.set_title("True Attack: Rule 5402 (sudo to ROOT, Level 3)\nESPM Score = 84.0 (Rank #1) vs Severity = 20.0", fontsize=10, fontweight="bold", color="#0f172a")
axL.set_xlim(0, 33)
axL.grid(axis="x", linestyle="--", alpha=0.4)
for idx, v in enumerate(c_true):
    axL.text(v + 0.5, idx, f"+{v:.1f} pts", va="center", fontsize=8.5, fontweight="bold", color="#0369a1")

# Right: False Positive IDS Noise (Rule 20101 Suricata TLS, level=6 -> ESPM 26.6)
c_fp = [3.6, 9.0, 5.25, 1.5, 2.0, 2.5, 6.0]
axR.barh(y, c_fp, color="#64748b", edgecolor="#475569")
axR.invert_yaxis()
axR.set_xlabel("Contribution to Priority Score (points out of 100)", fontsize=9.5)
axR.set_title("Benign Noise: Rule 20101 (Suricata TLS, Level 6)\nESPM Score = 29.8 (Suppressed) vs Severity = 40.0", fontsize=10, fontweight="bold", color="#0f172a")
axR.set_xlim(0, 33)
axR.grid(axis="x", linestyle="--", alpha=0.4)
for idx, v in enumerate(c_fp):
    axR.text(v + 0.5, idx, f"+{v:.1f} pts", va="center", fontsize=8.5, fontweight="bold", color="#475569")

plt.tight_layout()
save_all(fig, "fig_explainability.png")
print("Generated all figures successfully.")
