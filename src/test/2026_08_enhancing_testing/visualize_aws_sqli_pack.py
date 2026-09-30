"""
Same stacked-bar design as _6_visualize.ipynb (RD=Phase1, AD=Phase3, stacked
safe_blocked/harm_blocked/safe_bypassed/harm_bypassed), but comparing AWS WAF
before vs after the SQLi protection pack was attached, aggregated across all
5 seeds (250 payloads per bar instead of 50).

sql_injection / sql_injection_blind: "Base" uses the *.no_sqli_pack.jsonl
backup, "SQLi Pack" uses the current (post-pack) file. xss_*: no pack-related
change was made, so both panels use the same (current) data.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from constant import VALID_ATTACK_TYPES

HERE = Path(__file__).parent
HARMFUL_DIRS = {
    "PHASE_1": HERE / "output_generate_phase1_harmful",
    "PHASE_3": HERE / "output_generate_phase3_harmful",
}
FILE_PREFIXES = {"PHASE_1": "phase1", "PHASE_3": "phase3"}
SQLI_ATTACK_TYPES = {"sql_injection", "sql_injection_blind"}


def load_records(jsonl_path: Path) -> list:
    if not jsonl_path.exists():
        return []
    records = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def get_is_bypassed(record: dict):
    attack_result = record.get("attack_result")
    if attack_result is not None:
        return attack_result.get("is_bypassed")
    return record.get("is_bypassed")


def aggregate_counts(attack_type: str, phase: str, variant: str) -> dict:
    prefix = FILE_PREFIXES[phase]
    suffix = ".no_sqli_pack" if (variant == "base" and attack_type in SQLI_ATTACK_TYPES) else ""
    jsonl_path = HARMFUL_DIRS[phase] / f"{prefix}.AWS.{attack_type}{suffix}.jsonl"
    records = load_records(jsonl_path)

    counts = {"safe_blocked": 0, "harm_blocked": 0, "safe_bypassed": 0, "harm_bypassed": 0, "total_payload": 0}
    for record in records:
        is_bypassed = get_is_bypassed(record)
        is_harmful = record.get("is_harmful")
        counts["total_payload"] += 1
        if is_bypassed:
            counts["harm_bypassed" if is_harmful else "safe_bypassed"] += 1
        else:
            counts["harm_blocked" if is_harmful else "safe_blocked"] += 1
    return counts


def plot_aws_variant(variant: str, title: str, ax):
    phases = ["PHASE_1", "PHASE_3"]
    attack_types = VALID_ATTACK_TYPES

    x = np.arange(len(attack_types))
    width = 0.30

    colors = ["#814CAF", "#1A9F2C", "#E3B13D", "#FF0000"]
    labels = ["Safe Blocked", "Harm Blocked", "Safe Bypassed", "Harm Bypassed"]
    keys = ["safe_blocked", "harm_blocked", "safe_bypassed", "harm_bypassed"]

    for phase in phases:
        offset = -(width / 2 + 0.01) if phase == "PHASE_1" else (width / 2 + 0.01)
        counts = [aggregate_counts(attack_type, phase, variant) for attack_type in attack_types]
        safe_blocked = np.array([c["safe_blocked"] for c in counts])
        harm_blocked = np.array([c["harm_blocked"] for c in counts])
        safe_bypassed = np.array([c["safe_bypassed"] for c in counts])
        harm_bypassed = np.array([c["harm_bypassed"] for c in counts])
        total_payload = np.array([c["total_payload"] for c in counts])
        stacks = [safe_blocked, harm_blocked, safe_bypassed, harm_bypassed]

        bottom = np.zeros(len(attack_types))
        for key, color, label, values in zip(keys, colors, labels, stacks):
            show_label = label if phase == "PHASE_1" else None
            ax.bar(x + offset, values, width, bottom=bottom, label=show_label, color=color)
            bottom += values

        for j in range(len(attack_types)):
            total = total_payload[j] if total_payload[j] > 0 else 1
            y_offset = 0
            for val in [safe_blocked[j], harm_blocked[j], safe_bypassed[j], harm_bypassed[j]]:
                if val > 0:
                    percent = val * 100 / total
                    ax.text(x[j] + offset, y_offset + val / 2, f"{percent:.0f}%", ha="center", va="center", fontsize=7, color="black")
                y_offset += val
            phase_text = "RD" if phase == "PHASE_1" else "AD"
            max_height = safe_blocked[j] + harm_blocked[j] + safe_bypassed[j] + harm_bypassed[j]
            ax.text(x[j] + offset, max_height, phase_text, ha="center", va="bottom", fontsize=9, color="black", fontweight="bold")

    ax.set_ylabel("Number of Payloads")
    ax.set_title(title, y=1.05)
    ax.set_xticks(x)
    ax.set_xticklabels([attack_type.replace("sql_injection", "sqli") for attack_type in attack_types], rotation=0, fontweight="bold")
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    ax.set_axisbelow(True)


def main():
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.suptitle("AWS WAF - before vs after SQLi protection pack (5 seeds, 250 payloads/bar)", fontsize=14, fontweight="bold")

    plot_aws_variant("base", "AWS WAF - Base (no SQLi pack)", axes[0])
    plot_aws_variant("pack", "AWS WAF - SQLi Pack", axes[1])

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper right", bbox_to_anchor=(0.99, 0.95))
    fig.tight_layout(rect=[0, 0, 0.90, 0.93])

    out_path = HERE / "aws_sqli_pack_comparison.png"
    fig.savefig(out_path, dpi=150)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
