"""
Break down AWS SQLi bypass/blocked counts per seed, per phase, comparing the
no-pack baseline (*.no_sqli_pack.jsonl) against the current (post-pack)
results, for both Phase 1 (output_attack_phase1/) and Phase 3
(output_generate_phase3/).

Writes a Markdown report to AWS_sqli_pack_seed_breakdown.md next to this
script.
"""

import json
from pathlib import Path

from constant import SEEDS

HERE = Path(__file__).parent
ATTACK_TYPES = ["sql_injection", "sql_injection_blind"]

DATASETS = {
    "Phase 1": {
        "dir": HERE / "output_attack_phase1",
        "is_bypassed_path": ("attack_result", "is_bypassed"),
    },
    "Phase 3": {
        "dir": HERE / "output_generate_phase3",
        "is_bypassed_path": ("is_bypassed",),
    },
}


def get_is_bypassed(record: dict, path: tuple):
    value = record
    for key in path:
        if value is None:
            return None
        value = value.get(key)
    return value


def load_by_seed(jsonl_path: Path, is_bypassed_path: tuple) -> dict:
    by_seed = {seed: {"bypassed": 0, "blocked": 0, "error": 0} for seed in SEEDS}
    if not jsonl_path.exists():
        return by_seed
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            seed = record.get("seed")
            if seed not in by_seed:
                continue
            is_bypassed = get_is_bypassed(record, is_bypassed_path)
            if is_bypassed is True:
                by_seed[seed]["bypassed"] += 1
            elif is_bypassed is False:
                by_seed[seed]["blocked"] += 1
            else:
                by_seed[seed]["error"] += 1
    return by_seed


def render_table(lines: list, phase: str, attack_type: str, before: dict, after: dict):
    lines.append(f"### {phase} - {attack_type}")
    lines.append("")
    lines.append("| Seed | Before (no pack) bypassed/blocked/error | After (SQLi pack) bypassed/blocked/error |")
    lines.append("|---|---|---|")
    for seed in SEEDS:
        b = before[seed]
        a = after[seed]
        lines.append(
            f"| {seed} | {b['bypassed']}/{b['blocked']}/{b['error']} | {a['bypassed']}/{a['blocked']}/{a['error']} |"
        )
    total_before = {k: sum(before[seed][k] for seed in SEEDS) for k in ("bypassed", "blocked", "error")}
    total_after = {k: sum(after[seed][k] for seed in SEEDS) for k in ("bypassed", "blocked", "error")}
    lines.append(
        f"| **Total** | **{total_before['bypassed']}/{total_before['blocked']}/{total_before['error']}** | "
        f"**{total_after['bypassed']}/{total_after['blocked']}/{total_after['error']}** |"
    )
    lines.append("")


def main():
    lines = ["# AWS SQLi protection pack - bypass breakdown by seed", ""]
    for phase, cfg in DATASETS.items():
        for attack_type in ATTACK_TYPES:
            before_path = cfg["dir"] / f"phase{phase[-1]}.AWS.{attack_type}.no_sqli_pack.jsonl"
            after_path = cfg["dir"] / f"phase{phase[-1]}.AWS.{attack_type}.jsonl"
            before = load_by_seed(before_path, cfg["is_bypassed_path"])
            after = load_by_seed(after_path, cfg["is_bypassed_path"])
            render_table(lines, phase, attack_type, before, after)

    report_path = HERE / "AWS_sqli_pack_seed_breakdown.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {report_path}")
    print()
    print("\n".join(lines))


if __name__ == "__main__":
    main()
