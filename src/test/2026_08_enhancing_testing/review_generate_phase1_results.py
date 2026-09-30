"""
Verify completeness of Phase 1 payload generation output.

Checks every (waf_name, attack_type, seed, run_index) combination expected by
generate_payloads.py against what is actually present in output/phase1.<waf>.
<attack_type>.jsonl, and reports missing entries, duplicates, and unparsable
lines.
"""

import argparse
import json
from pathlib import Path

WAF_NAMES = ["ModSecurity", "Naxsi", "Cloudflare", "AWS"]

VALID_ATTACK_TYPES = [
    "xss_dom",
    "xss_reflected",
    "xss_stored",
    "sql_injection",
    "sql_injection_blind",
]

from constant import SEEDS
NUM_PAYLOADS_PER_RUN = 50

OUTPUT_DIR = Path(__file__).parent / "output_generate_phase1"


def scan_file(jsonl_path: Path):
    """Return (keys, duplicate_keys, bad_lines) for one jsonl file."""
    keys = set()
    duplicate_keys = []
    bad_lines = []

    if not jsonl_path.exists():
        return keys, duplicate_keys, bad_lines

    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                bad_lines.append((line_no, f"invalid JSON: {e}"))
                continue

            seed = record.get("seed")
            run_index = record.get("run_index")
            if seed is None or run_index is None:
                bad_lines.append((line_no, f"missing seed/run_index: seed={seed!r}, run_index={run_index!r}"))
                continue

            key = (seed, run_index)
            if key in keys:
                duplicate_keys.append((line_no, key))
            keys.add(key)

    return keys, duplicate_keys, bad_lines


def main():
    parser = argparse.ArgumentParser(description="Check completeness of Phase 1 payload generation output.")
    parser.add_argument("--waf", choices=WAF_NAMES, default=None, help="Only check this WAF name.")
    parser.add_argument("--attack-type", choices=VALID_ATTACK_TYPES, default=None, help="Only check this attack type.")
    parser.add_argument("--num-payloads", type=int, default=NUM_PAYLOADS_PER_RUN, help="Expected payloads per (waf, attack_type, seed) run.")
    parser.add_argument("--seeds", type=int, nargs="+", default=SEEDS, help="Expected random seeds.")
    parser.add_argument("--show-missing", action="store_true", help="List every missing (seed, run_index), not just counts.")
    args = parser.parse_args()

    wafs = [args.waf] if args.waf else WAF_NAMES
    attack_types = [args.attack_type] if args.attack_type else VALID_ATTACK_TYPES
    expected_keys = {(seed, run_index) for seed in args.seeds for run_index in range(args.num_payloads)}
    expected_total_per_file = len(expected_keys)

    print("=" * 70)
    print("PHASE 1 OUTPUT COMPLETENESS CHECK")
    print("=" * 70)
    print(f"Expected per (waf, attack_type): {len(args.seeds)} seeds x {args.num_payloads} payloads = {expected_total_per_file}")
    print("-" * 70)

    grand_expected = 0
    grand_found = 0
    grand_missing = 0
    grand_duplicates = 0
    grand_bad_lines = 0
    problem_files = []

    for waf_name in wafs:
        for attack_type in attack_types:
            jsonl_path = OUTPUT_DIR / f"phase1.{waf_name}.{attack_type}.jsonl"
            keys, duplicate_keys, bad_lines = scan_file(jsonl_path)

            missing_keys = expected_keys - keys
            unexpected_keys = keys - expected_keys

            grand_expected += expected_total_per_file
            grand_found += len(keys & expected_keys)
            grand_missing += len(missing_keys)
            grand_duplicates += len(duplicate_keys)
            grand_bad_lines += len(bad_lines)

            status = "OK"
            if not jsonl_path.exists():
                status = "FILE MISSING"
            elif missing_keys or duplicate_keys or bad_lines or unexpected_keys:
                status = "ISSUES"

            if status != "OK":
                problem_files.append(jsonl_path.name)

            print(f"{waf_name:<12} {attack_type:<22} found={len(keys & expected_keys):>4}/{expected_total_per_file} "
                  f"missing={len(missing_keys):>4} dup={len(duplicate_keys):>3} bad_lines={len(bad_lines):>3} "
                  f"unexpected={len(unexpected_keys):>3}  [{status}]")

            for seed in args.seeds:
                seed_found = sum(1 for k in keys if k[0] == seed and k[1] < args.num_payloads)
                seed_missing = args.num_payloads - seed_found
                seed_status = "OK" if seed_missing == 0 else "ISSUES"
                print(f"    seed={seed:<8} found={seed_found:>4}/{args.num_payloads:<4} missing={seed_missing:>4}  [{seed_status}]")

            if args.show_missing and missing_keys:
                for seed, run_index in sorted(missing_keys):
                    print(f"    MISSING seed={seed} run_index={run_index}")
            for line_no, key in duplicate_keys:
                print(f"    DUPLICATE at line {line_no}: seed={key[0]} run_index={key[1]}")
            for line_no, reason in bad_lines:
                print(f"    BAD LINE {line_no}: {reason}")
            if unexpected_keys and args.show_missing:
                for seed, run_index in sorted(unexpected_keys):
                    print(f"    UNEXPECTED seed={seed} run_index={run_index} (not in requested --seeds/--num-payloads)")

    print("-" * 70)
    print(f"TOTAL expected : {grand_expected}")
    print(f"TOTAL found    : {grand_found}")
    print(f"TOTAL missing  : {grand_missing}")
    print(f"TOTAL duplicate: {grand_duplicates}")
    print(f"TOTAL bad lines: {grand_bad_lines}")
    print("=" * 70)

    if problem_files:
        print(f"Files with issues ({len(problem_files)}):")
        for name in problem_files:
            print(f"  - {name}")
    else:
        print("All files complete, no duplicates, no bad lines.")


if __name__ == "__main__":
    main()
