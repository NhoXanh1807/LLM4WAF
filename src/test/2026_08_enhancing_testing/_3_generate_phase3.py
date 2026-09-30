"""
Task 3 - Phase 3 payload generation using probe history.

For each (waf_name, attack_type) pair, reads the attacked Phase 1 results
from output_attack_phase1/phase1.<waf_name>.<attack_type>.jsonl. Records are
grouped by seed (seeds are kept independent - a probe_history sample never
mixes records from different seeds). For each seed, NUM_PAYLOADS_PER_RUN
runs are generated; each run samples PROBE_HISTORY_SIZE random records
(bypassed and blocked alike) from that seed's records to use as probe_history,
then asks LLMShield for one new payload conditioned on that history.

Payloads are requested from the LLMShield API (main.py, action=generate_payload_batch)
running on the GPU VM, via LLMSHIELD_ENDPOINT in src/core/.env. Each generated
payload is then immediately sent against its target WAF (same async httpx
approach as _2_attack_phase1.py) so status_code/is_bypassed are already filled
in before the record is written to output_generate_phase3/.
"""

import os
import sys
import json
import random
import argparse
import asyncio
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import TextIO

import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../core")))

from external_services import llmshield  # noqa: E402
from models.dtos import PayloadResult  # noqa: E402


from constant import SEEDS, WAF_NAMES, VALID_ATTACK_TYPES, WAF_DOMAINS

NUM_PAYLOADS_PER_RUN = 50
PROBE_HISTORY_SIZE = 10

INPUT_DIR = Path(__file__).parent / "output_attack_phase1"
OUTPUT_DIR = Path(__file__).parent / "output_generate_phase3"

ATTACK_HEADERS = {"X-Lab-Key": "llmshield-lab-only"}
ATTACK_CONCURRENCY = 30
ATTACK_TIMEOUT = 15.0


@dataclass
class SeededPayloadResult(PayloadResult):
    waf_name: str = None
    seed: int = None
    run_index: int = None
    probe_history: list = field(default_factory=list)


def now_str():
    return datetime.now(timezone(timedelta(hours=7))).strftime("%Y-%m-%d %H:%M:%S")


def load_seed_records(jsonl_path: Path) -> dict:
    """Load attacked Phase 1 records from jsonl_path, grouped by seed.

    Each record is flattened to {payload, technique, is_bypassed} - the shape
    LLMShield's _build_phase3_prompt expects for probe_history entries.
    """
    records_by_seed = {}  # seed -> [dict, ...]
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            attack_result = record.get("attack_result") or {}
            is_bypassed = attack_result.get("is_bypassed")
            if is_bypassed is None:
                continue  # errored/unattacked request, unusable as probe history
            seed = record.get("seed")
            records_by_seed.setdefault(seed, []).append({
                "payload": record["payload"],
                "technique": record["technique"],
                "is_bypassed": is_bypassed,
            })
    return records_by_seed


async def attack_one(client: httpx.AsyncClient, domain: str, payload: str, semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        try:
            response = await client.get(f"{domain}/portal/search", params={"keyword": payload}, headers=ATTACK_HEADERS)
            return {"status_code": response.status_code, "is_bypassed": response.status_code != 403}
        except Exception as e:
            return {"status_code": None, "is_bypassed": None, "error": str(e)}


async def attack_results_async(results: list) -> None:
    """Attack each generated payload against its target WAF and fill in
    status_code/is_bypassed on the result in place."""
    semaphore = asyncio.Semaphore(ATTACK_CONCURRENCY)
    async with httpx.AsyncClient(timeout=ATTACK_TIMEOUT) as client:
        tasks = [attack_one(client, WAF_DOMAINS[r.waf_name], r.payload, semaphore) for r in results]
        attack_results = await asyncio.gather(*tasks)
    for result, attack_result in zip(results, attack_results):
        result.status_code = attack_result["status_code"]
        result.is_bypassed = attack_result["is_bypassed"]


def attack_results(results: list) -> None:
    asyncio.run(attack_results_async(results))


def sample_probe_history(records: list, seed: int, run_index: int, probe_history_size: int) -> list:
    # Each (seed, run_index) gets its own deterministic RNG, independent of
    # execution order, so tasks can be skipped/resumed/parallelized freely.
    rng = random.Random(seed * 100000 + run_index)
    k = min(probe_history_size, len(records))
    return rng.sample(records, k)


def generate_batch_for_tasks(tasks: list) -> list[SeededPayloadResult]:
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
            "probe_history": t.probe_history,
            "adapter_name": "phase3_rl",
            "seed": seed,
        }
        for t in tasks
    ]
    payloads = llmshield.llmshield_generate_payloads_batch(items)
    return [
        SeededPayloadResult(
            payload=payload,
            technique=None,
            attack_type=t.attack_type,
            waf_name=t.waf_name,
            seed=t.seed,
            run_index=t.run_index,
            probe_history=t.probe_history,
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
    probe_history: list


def main():
    parser = argparse.ArgumentParser(description="Generate Phase 3 payloads conditioned on Phase 1 attack probe history.")
    parser.add_argument("--waf", choices=WAF_NAMES, default=None, help="Only generate for this WAF name.")
    parser.add_argument("--attack-type", choices=VALID_ATTACK_TYPES, default=None, help="Only generate for this attack type.")
    parser.add_argument("--num-payloads", type=int, default=NUM_PAYLOADS_PER_RUN, help="Payloads per (waf, attack_type, seed) run.")
    parser.add_argument("--seeds", type=int, nargs="+", default=SEEDS, help="Random seeds to run.")
    parser.add_argument("--probe-history-size", type=int, default=PROBE_HISTORY_SIZE, help="Number of Phase 1 records randomly sampled (per run) to build probe_history.")
    parser.add_argument("--dry-run", action="store_true", help="Only print the task summary, do not generate.")
    parser.add_argument("--batch-size", type=int, default=NUM_PAYLOADS_PER_RUN, help="Payloads sent to LLMShield per batched request (i.e. per model.generate() call). Can exceed num-payloads: batches then merge multiple waf/attack_type runs sharing the same seed.")
    args = parser.parse_args()

    wafs = [args.waf] if args.waf else WAF_NAMES
    attack_types = [args.attack_type] if args.attack_type else VALID_ATTACK_TYPES

    # Build the full list of pending (not-yet-generated) tasks up front.
    tasks = []  # type: list[Task]
    skipped_no_input = []
    for waf_name in wafs:
        for attack_type in attack_types:
            input_path = INPUT_DIR / f"phase1.{waf_name}.{attack_type}.jsonl"
            if not input_path.exists():
                skipped_no_input.append(input_path.name)
                continue
            records_by_seed = load_seed_records(input_path)

            jsonl_path = OUTPUT_DIR / f"phase3.{waf_name}.{attack_type}.jsonl"
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            done_keys = load_done_keys(jsonl_path)

            for seed in args.seeds:
                seed_records = records_by_seed.get(seed, [])
                if not seed_records:
                    continue
                for run_index in range(args.num_payloads):
                    if (seed, run_index) in done_keys:
                        continue
                    probe_history = sample_probe_history(seed_records, seed, run_index, args.probe_history_size)
                    tasks.append(Task(waf_name, attack_type, seed, run_index, jsonl_path, probe_history))

    total_planned = len(wafs) * len(attack_types) * len(args.seeds) * args.num_payloads

    print("=" * 60)
    print("PHASE 3 PAYLOAD GENERATION - TASK SUMMARY")
    print("=" * 60)
    print(f"WAFs               : {', '.join(wafs)}")
    print(f"Attack types       : {', '.join(attack_types)}")
    print(f"Seeds              : {args.seeds}")
    print(f"Payloads/run       : {args.num_payloads}")
    print(f"Probe history size : {args.probe_history_size}")
    print(f"Total planned      : {total_planned}")
    print(f"Already done       : {total_planned - len(tasks) - sum(1 for _ in skipped_no_input)}")
    print(f"To generate        : {len(tasks)}")
    if skipped_no_input:
        print(f"Missing input (no output_attack_phase1 file): {', '.join(skipped_no_input)}")
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
                attack_results(results)
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
