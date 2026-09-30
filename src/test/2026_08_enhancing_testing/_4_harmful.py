"""
Task 4 - Compute is_harmful for every generated payload (Phase 1 + Phase 3).

Reads Phase 1 / Phase 3 results and computes is_harmful for every record
(regardless of is_bypassed) via the same validators used by
attack_pipeline.py._3_test_attack:
  - XSS  -> external_services.xss_harmfulness_validator.evaluate_xss_payload
  - SQLi -> services.sql_harmfulness_validator.evaluate_sql_payload

Phase 1 input is output_attack_phase1/phase1.*.jsonl (the already-attacked
Phase 1 payloads - output_generate_phase1/ itself has is_bypassed=null since
it is pre-attack). Phase 3 input is output_generate_phase3/phase3.*.jsonl,
which already carries its own is_bypassed/status_code from _3_generate_phase3.py.

Output is split per phase: output_generate_phase1_harmful/ and
output_generate_phase3_harmful/, mirroring the input filenames.
"""

import os
import sys
import json
import argparse
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../core")))

from services.sql_harmfulness_validator import evaluate_sql_payload  # noqa: E402
from external_services.xss_harmfulness_validator import evaluate_xss_payload  # noqa: E402

from constant import WAF_NAMES, VALID_ATTACK_TYPES  # noqa: E402

INPUT_DIRS = {
    "1": Path(__file__).parent / "output_attack_phase1",
    "3": Path(__file__).parent / "output_generate_phase3",
}
OUTPUT_DIRS = {
    "1": Path(__file__).parent / "output_generate_phase1_harmful",
    "3": Path(__file__).parent / "output_generate_phase3_harmful",
}
FILE_PREFIXES = {
    "1": "phase1",
    "3": "phase3",
}


def now_str():
    return datetime.now(timezone(timedelta(hours=7))).strftime("%Y-%m-%d %H:%M:%S")


def load_records(jsonl_path: Path) -> list:
    records = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def compute_is_harmful(payload: str, attack_type: str) -> bool | None:
    if "xss" in attack_type.lower():
        result = evaluate_xss_payload(payload)
        if result is None:
            return None
        return not result.is_safe
    elif "sql" in attack_type.lower():
        result = evaluate_sql_payload(payload)
        if result is None:
            return None
        return len(result.harm_queries) > 0
    return None


def load_done_harmful(out_path: Path) -> dict:
    """Resume support: payload -> is_harmful already computed in a previous run,
    read from this script's own output file (the input file's is_harmful is
    always null - only output_generate_phase*_harmful/ ever gets it filled in)."""
    done = {}
    if not out_path.exists():
        return done
    for record in load_records(out_path):
        if record.get("is_harmful") is not None:
            done[record.get("payload")] = record["is_harmful"]
    return done


def process_file(jsonl_path: Path, out_path: Path, force: bool, progress: dict) -> None:
    records = load_records(jsonl_path)

    done_harmful = {} if force else load_done_harmful(out_path)
    if done_harmful:
        for record in records:
            if record.get("is_harmful") is None and record.get("payload") in done_harmful:
                record["is_harmful"] = done_harmful[record["payload"]]

    pending = [r for r in records if force or r.get("is_harmful") is None]

    harmful = 0
    for i, record in enumerate(pending):
        if i % 20 == 0 or i == len(pending) - 1:
            remaining = progress["total_pending"] - progress["done"]
            avg = progress["total_elapsed"] / progress["done"] if progress["done"] > 0 else None
            eta_str = f", avg={avg:.2f}s/payload, eta={timedelta(seconds=int(avg * remaining))}" if avg else ""
            print(f"  [{now_str()}] {jsonl_path.name} | done {progress['done']}/{progress['total_pending']}{eta_str}")

        payload = record.get("payload", "")
        attack_type = record.get("attack_type", "")
        start = time.perf_counter()
        is_harmful = compute_is_harmful(payload, attack_type)
        progress["total_elapsed"] += time.perf_counter() - start
        progress["done"] += 1

        record["is_harmful"] = is_harmful
        if is_harmful:
            harmful += 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"  [{now_str()}] {jsonl_path.name}: {len(records)} records, tested={len(pending)}, harmful={harmful}")


def count_pending(jsonl_path: Path, out_path: Path, force: bool) -> int:
    if force:
        return len(load_records(jsonl_path))
    records = load_records(jsonl_path)
    done_harmful = load_done_harmful(out_path)
    return sum(
        1 for r in records
        if r.get("is_harmful") is None and r.get("payload") not in done_harmful
    )


def main():
    parser = argparse.ArgumentParser(description="Compute is_harmful for every Phase 1 / Phase 3 payload.")
    parser.add_argument("--phase", type=int, nargs="+", choices=[1, 3], default=[1, 3], help="Which phase(s) to process (default: both 1 and 3).")
    parser.add_argument("--waf", choices=WAF_NAMES, default=None, help="Only process this WAF name.")
    parser.add_argument("--attack-type", choices=VALID_ATTACK_TYPES, default=None, help="Only process this attack type.")
    parser.add_argument("--force", action="store_true", help="Recompute is_harmful even if already set (default: skip already-tested records).")
    parser.add_argument("--dry-run", action="store_true", help="Only print the task summary, do not compute.")
    args = parser.parse_args()

    phases = [str(p) for p in args.phase]

    # Resolve the file list per phase up front so we can print one combined
    # task summary (mirrors _1/_3 generate scripts) before doing any work.
    phase_files = {}  # phase -> [Path, ...]
    for phase in phases:
        input_dir = INPUT_DIRS[phase]
        prefix = FILE_PREFIXES[phase]
        jsonl_files = sorted(input_dir.glob(f"{prefix}.*.jsonl"))
        if args.waf:
            jsonl_files = [p for p in jsonl_files if p.stem.split(".")[1] == args.waf]
        if args.attack_type:
            jsonl_files = [p for p in jsonl_files if p.stem.split(".")[2] == args.attack_type]
        phase_files[phase] = jsonl_files

    print("=" * 60)
    print("PHASE HARMFULNESS CHECK - TASK SUMMARY")
    print("=" * 60)
    total_pending = 0
    for phase in phases:
        jsonl_files = phase_files[phase]
        if not jsonl_files:
            print(f"  phase{phase}: no matching jsonl files found in {INPUT_DIRS[phase]}")
            continue
        output_dir = OUTPUT_DIRS[phase]
        for jsonl_path in jsonl_files:
            pending = count_pending(jsonl_path, output_dir / jsonl_path.name, args.force)
            total_pending += pending
            print(f"  phase{phase:<2} {jsonl_path.name:<45} pending={pending}")
    print("-" * 60)
    print(f"Total payloads to test: {total_pending}")
    print("=" * 60)

    if args.dry_run or total_pending == 0:
        return

    progress = {"total_pending": total_pending, "done": 0, "total_elapsed": 0.0}
    for phase in phases:
        jsonl_files = phase_files[phase]
        if not jsonl_files:
            continue
        output_dir = OUTPUT_DIRS[phase]
        print(f"[{now_str()}] phase{phase} - {len(jsonl_files)} file(s)")
        for jsonl_path in jsonl_files:
            out_path = output_dir / jsonl_path.name
            process_file(jsonl_path, out_path, args.force, progress)


if __name__ == "__main__":
    main()
