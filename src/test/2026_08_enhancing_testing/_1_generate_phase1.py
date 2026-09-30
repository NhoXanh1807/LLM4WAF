"""
Task 3 - Phase 1 payload generation with multiple random seeds.

For each (waf_name, attack_type) pair, generate 5 runs of 50 payloads each,
one run per random seed. Each generated payload is appended as one line to
<waf_name>.<attack_type>.jsonl (JSON Lines), storing the same fields as the
old test scripts (payload, technique, attack_type, status_code, is_bypassed,
is_harmful) plus the seed/run metadata used to produce it.

Payloads are requested from the LLMShield API (main.py, action=generate_payload)
running on the GPU VM, via LLMSHIELD_ENDPOINT in src/core/.env.
"""

import os
import sys
import json
import random
import argparse
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import TextIO

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../core")))

from external_services import llmshield  # noqa: E402
from models.dtos import PayloadResult  # noqa: E402


from constant import SEEDS, WAF_NAMES, VALID_ATTACK_TYPES

NUM_PAYLOADS_PER_RUN = 50

ATTACK_OBFUSCATE_TECHNIQUES = {
    "xss": [
        "obf_double_url_encode+obf_case_random_full_bypass",
        "Event Handler XSS (heuristic)_adv_obf_full_bypass",
        "obf_url_encode+obf_case_random_full_bypass",
        "obf_whitespace_url+obf_case_random_full_bypass",
        "Direct JS Call XSS (manual refine)_non_script_xss",
        "obf_double_url_encode+obf_whitespace_url_full_bypass",
        "SVG onEvent_adv_obf_full_bypass",
        "IMG onerror+Body onLoad_adv_obf_full_bypass",
    ],
    "sqli": [
        "obf_double_url_encode+obf_whitespace_url+obf_comment_sql_full_bypass",
        "obf_comment_sql+obf_double_url_encode_adv_obf_full_bypass",
        "obf_case_random+obf_comment_sql_version+obf_double_url_encode_full_bypass",
        "obf_double_url_encode+obf_url_encode_adv_obf_full_bypass",
        "obf_whitespace_url+obf_comment_sql_version+obf_double_url_encode_adv_obf_full_bypass",
        "Boolean-based Blind_full_bypass",
        "Time-based Blind_full_bypass",
        "Union Select Null Bytes_adv_obf_full_bypass",
        "obf_case_random+obf_double_url_encode_adv_obf_full_bypass",
    ],
}

OUTPUT_DIR = Path(__file__).parent / "output_generate_phase1"


@dataclass
class SeededPayloadResult(PayloadResult):
    seed: int = None
    run_index: int = None


def now_str():
    return datetime.now(timezone(timedelta(hours=7))).strftime("%Y-%m-%d %H:%M:%S")


def pick_technique(attack_type: str, seed: int, run_index: int) -> str:
    # Each (seed, run_index) gets its own deterministic RNG, independent of
    # execution order, so tasks can be skipped/resumed/parallelized freely.
    rng = random.Random(seed * 100000 + run_index)
    technique_pool = ATTACK_OBFUSCATE_TECHNIQUES["xss"] if "xss" in attack_type.lower() else ATTACK_OBFUSCATE_TECHNIQUES["sqli"]
    selected_techniques = rng.sample(technique_pool, rng.randint(1, int(len(technique_pool) / 2)))
    return "+".join(selected_techniques)


def generate_batch_for_tasks(tasks: list) -> list:
    """Generate payloads for a list of Task in a single batched LLMShield
    request. All tasks must share the same seed (one torch.manual_seed per
    request), but can span different waf_name/attack_type - this is what lets
    batches grow past NUM_PAYLOADS_PER_RUN by merging multiple runs together."""
    seed = tasks[0].seed
    assert all(t.seed == seed for t in tasks), "generate_batch_for_tasks requires a single shared seed"

    items = [
        {
            "waf_name": t.waf_name,
            "attack_type": t.attack_type,
            "technique": t.technique,
            "adapter_name": "phase1",
            "seed": seed,
        }
        for t in tasks
    ]
    payloads = llmshield.llmshield_generate_payloads_batch(items)
    return [
        SeededPayloadResult(
            payload=payload,
            technique=t.technique,
            attack_type=t.attack_type,
            seed=t.seed,
            run_index=t.run_index,
        )
        for t, payload in zip(tasks, payloads)
    ]


def load_done_keys(jsonl_path: Path) -> set:
    """Resume support: set of (seed, run_index) already written to the file."""
    done = set()
    if not jsonl_path.exists():
        return done
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                done.add((record.get("seed"), record.get("run_index")))
            except json.JSONDecodeError:
                continue
    return done

@dataclass
class Task:
    waf_name: str
    attack_type: str
    seed: int
    run_index: int
    jsonl_path: Path
    technique: str


def main():
    parser = argparse.ArgumentParser(description="Generate Phase 1 payloads with multiple random seeds.")
    parser.add_argument("--waf", choices=WAF_NAMES, default=None, help="Only generate for this WAF name.")
    parser.add_argument("--attack-type", choices=VALID_ATTACK_TYPES, default=None, help="Only generate for this attack type.")
    parser.add_argument("--num-payloads", type=int, default=NUM_PAYLOADS_PER_RUN, help="Payloads per (waf, attack_type, seed) run.")
    parser.add_argument("--seeds", type=int, nargs="+", default=SEEDS, help="Random seeds to run.")
    parser.add_argument("--dry-run", action="store_true", help="Only print the task summary, do not generate.")
    parser.add_argument("--batch-size", type=int, default=NUM_PAYLOADS_PER_RUN, help="Payloads sent to LLMShield per batched request (i.e. per model.generate() call). Can exceed num-payloads: batches then merge multiple waf/attack_type runs sharing the same seed.")
    args = parser.parse_args()

    wafs = [args.waf] if args.waf else WAF_NAMES
    attack_types = [args.attack_type] if args.attack_type else VALID_ATTACK_TYPES

    # Build the full list of pending (not-yet-generated) tasks up front.
    tasks = [] #type: list[Task]
    for waf_name in wafs:
        for attack_type in attack_types:
            jsonl_path = OUTPUT_DIR / f"phase1.{waf_name}.{attack_type}.jsonl"
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            done_keys = load_done_keys(jsonl_path)
            for seed in args.seeds:
                for run_index in range(args.num_payloads):
                    if (seed, run_index) in done_keys:
                        continue
                    technique = pick_technique(attack_type, seed, run_index)
                    tasks.append(Task(waf_name, attack_type, seed, run_index, jsonl_path, technique))

    total_planned = len(wafs) * len(attack_types) * len(args.seeds) * args.num_payloads

    print("=" * 60)
    print("PHASE 1 PAYLOAD GENERATION - TASK SUMMARY")
    print("=" * 60)
    print(f"WAFs           : {', '.join(wafs)}")
    print(f"Attack types   : {', '.join(attack_types)}")
    print(f"Seeds          : {args.seeds}")
    print(f"Payloads/run   : {args.num_payloads}")
    print(f"Total planned  : {total_planned}")
    print(f"Already done   : {total_planned - len(tasks)}")
    print(f"To generate    : {len(tasks)}")
    print("-" * 60)
    for waf_name in wafs:
        for attack_type in attack_types:
            pending = sum(1 for t in tasks if t.waf_name == waf_name and t.attack_type == attack_type)
            print(f"  {waf_name:<12} {attack_type:<22} pending={pending}/{len(args.seeds) * args.num_payloads}")
    print("=" * 60)

    if args.dry_run or not tasks:
        return

    # Group pending tasks by seed only (not by waf/attack_type), so batches can
    # merge multiple (waf, attack_type) runs that share a seed into one bigger
    # LLMShield request -> one model.generate() call handling >NUM_PAYLOADS_PER_RUN
    # prompts at once. torch.manual_seed() is set once per request, so mixing
    # different seeds in the same batch is not valid - only same-seed tasks merge.
    seed_groups = {}  # seed -> [Task, ...]
    for task in tasks:
        seed_groups.setdefault(task.seed, []).append(task)

    open_files = {}  # type: dict[Path, TextIO]
    total_elapsed = 0.0
    generated_count = 0
    num_seeds = len(seed_groups)
    try:
        for si, (seed, seed_tasks) in enumerate(seed_groups.items(), start=1):
            print(f"[{now_str()}] seed group ({si}/{num_seeds}) seed={seed} payloads={len(seed_tasks)}")

            num_chunks = (len(seed_tasks) + args.batch_size - 1) // args.batch_size
            for ci, chunk_start in enumerate(range(0, len(seed_tasks), args.batch_size), start=1):
                chunk = seed_tasks[chunk_start:chunk_start + args.batch_size]

                remaining_payloads = len(tasks) - generated_count
                avg_per_payload = total_elapsed / generated_count if generated_count > 0 else None
                eta_str = f", avg={avg_per_payload:.2f}s/payload, eta={timedelta(seconds=int(avg_per_payload * remaining_payloads))}" if avg_per_payload else ""
                waf_attack_summary = ", ".join(sorted({f"{t.waf_name}/{t.attack_type}" for t in chunk}))
                print(f"  [{now_str()}] chunk ({ci}/{num_chunks}) [{waf_attack_summary}] ({len(chunk)} payloads) | done {generated_count}/{len(tasks)}{eta_str}")

                start = time.perf_counter()
                results = generate_batch_for_tasks(chunk)
                total_elapsed += time.perf_counter() - start

                for task, result in zip(chunk, results):
                    if task.jsonl_path not in open_files:
                        open_files[task.jsonl_path] = open(task.jsonl_path, "a", encoding="utf-8")
                    open_files[task.jsonl_path].write(json.dumps(asdict(result), ensure_ascii=False) + "\n")
                for task in chunk:
                    open_files[task.jsonl_path].flush()
                generated_count += len(chunk)
    finally:
        for f in open_files.values():
            f.close()


if __name__ == "__main__":
    main()
