"""
Same stacked-bar design as _6_visualize.ipynb (RD=Phase1, AD=Phase3, stacked
safe_blocked/harm_blocked/safe_bypassed/harm_bypassed), but comparing AWS WAF
before vs after the SQLi protection pack was attached.

sql_injection / sql_injection_blind: "Base" uses the real, original April
2026 50-payload batches (test_gemma2_2b_all_techniques_2026_04_13/logs/
2026-04-13_22-14-32/result_AWS_*.txt + phase3_AWS_*.txt - the actual
historical attack, not a recent re-generation), "SQLi Pack" uses
replay_april_aws_payloads.py's re-attack of those exact same payloads
against the current, pack-enabled AWS WAF (output_replay_april_aws/). This
is a payload-identical before/after comparison. xss_*: no pack-related
change was made, so both panels use the current 5-seed data (250
payloads/bar) from output_generate_phase{1,3}_harmful/.
"""

import json
import os
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from constant import VALID_ATTACK_TYPES

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../core")))
from services.sql_harmfulness_validator import evaluate_sql_payload  # noqa: E402

HERE = Path(__file__).parent
HARMFUL_DIRS = {
    "PHASE_1": HERE / "output_generate_phase1_harmful",
    "PHASE_3": HERE / "output_generate_phase3_harmful",
}
FILE_PREFIXES = {"PHASE_1": "phase1", "PHASE_3": "phase3"}
SQLI_ATTACK_TYPES = {"sql_injection", "sql_injection_blind"}

APRIL_LOG_DIR = (
    HERE.parent / "test_gemma2_2b_all_techniques_2026_04_13" / "logs" / "2026-04-13_22-14-32"
)
APRIL_SQLI_BASE_FILES = {
    "PHASE_1": lambda attack_type: APRIL_LOG_DIR / f"result_AWS_{attack_type}.txt",
    "PHASE_3": lambda attack_type: APRIL_LOG_DIR / f"phase3_AWS_{attack_type}.txt",
}
REPLAY_DIR = HERE / "output_replay_april_aws"
REPLAY_SQLI_PACK_FILES = {
    "PHASE_1": lambda attack_type: REPLAY_DIR / f"phase1.AWS.{attack_type}.jsonl",
    "PHASE_3": lambda attack_type: REPLAY_DIR / f"phase3.AWS.{attack_type}.jsonl",
}

_harmful_cache = {}


def is_sql_harmful(payload: str) -> bool:
    if payload not in _harmful_cache:
        result = evaluate_sql_payload(payload)
        _harmful_cache[payload] = bool(result and len(result.harm_queries) > 0)
    return _harmful_cache[payload]


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
    counts = {"safe_blocked": 0, "harm_blocked": 0, "safe_bypassed": 0, "harm_bypassed": 0, "total_payload": 0}

    if attack_type in SQLI_ATTACK_TYPES:
        # Real April payloads (base) / the same payloads replayed against the
        # current pack-enabled WAF (pack) - is_harmful isn't precomputed for
        # either, so it's derived on the fly with the same SQL validator
        # _4_harmful.py uses.
        path_fn = APRIL_SQLI_BASE_FILES[phase] if variant == "base" else REPLAY_SQLI_PACK_FILES[phase]
        records = load_records(path_fn(attack_type))
        for record in records:
            is_bypassed = record.get("is_bypassed", record.get("bypassed"))
            is_harmful = is_sql_harmful(record["payload"])
            counts["total_payload"] += 1
            if is_bypassed:
                counts["harm_bypassed" if is_harmful else "safe_bypassed"] += 1
            else:
                counts["harm_blocked" if is_harmful else "safe_blocked"] += 1
        return counts

    prefix = FILE_PREFIXES[phase]
    jsonl_path = HARMFUL_DIRS[phase] / f"{prefix}.AWS.{attack_type}.jsonl"
    records = load_records(jsonl_path)
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
    fig.suptitle(
        "AWS WAF - before vs after SQLi protection pack\n"
        "(sqli/sqli_blind: real April 2026 50-payload batch, replayed as-is; xss_*: current 5-seed data, 250/bar)",
        fontsize=13, fontweight="bold",
    )

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
