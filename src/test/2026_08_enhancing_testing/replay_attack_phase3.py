"""
Re-attack already-generated Phase 3 payloads against their target WAF and
refresh status_code/is_bypassed in place, without calling LLMShield again.

Unlike Phase 1 (_1_generate_phase1.py + _2_attack_phase1.py, which are split
so the attack step alone can be re-run), Phase 3 generates and attacks in one
pass (_3_generate_phase3.py). This script covers the missing "attack-only"
step for Phase 3: reads output_generate_phase3/phase3.<WafName>.<attack_type>.jsonl,
re-sends each payload with the same async httpx client as _2_attack_phase1.py,
and overwrites status_code/is_bypassed on each record.
"""

import argparse
import asyncio
import json
from pathlib import Path

import httpx

from constant import WAF_DOMAINS

HEADERS = {"X-Lab-Key": "llmshield-lab-only"}

INPUT_DIR = Path(__file__).parent / "output_generate_phase3"


def load_records(jsonl_path: Path) -> list:
    records = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


async def attack_one(client: httpx.AsyncClient, domain: str, payload: str, semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        try:
            response = await client.get(f"{domain}/portal/search", params={"keyword": payload}, headers=HEADERS)
            return {"status_code": response.status_code, "is_bypassed": response.status_code != 403}
        except Exception as e:
            return {"status_code": None, "is_bypassed": None, "error": str(e)}


async def attack_file(waf_name: str, jsonl_path: Path, concurrency: int, timeout: float):
    domain = WAF_DOMAINS[waf_name]
    records = load_records(jsonl_path)

    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [attack_one(client, domain, r["payload"], semaphore) for r in records]
        results = await asyncio.gather(*tasks)

    for record, attack_result in zip(records, results):
        record["status_code"] = attack_result["status_code"]
        record["is_bypassed"] = attack_result["is_bypassed"]
        if "error" in attack_result:
            record["attack_error"] = attack_result["error"]
        else:
            record.pop("attack_error", None)

    with open(jsonl_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    bypassed = sum(1 for r in results if r["is_bypassed"] is True)
    blocked = sum(1 for r in results if r["is_bypassed"] is False)
    errored = sum(1 for r in results if r["is_bypassed"] is None)
    print(f"[{waf_name}] {jsonl_path.name}: {len(records)} payloads -> bypassed={bypassed} blocked={blocked} error={errored}")


async def main_async(args):
    jsonl_files = [p for p in sorted(INPUT_DIR.glob("phase3.*.jsonl")) if len(p.stem.split(".")) == 3]
    if args.waf:
        jsonl_files = [p for p in jsonl_files if p.name.split(".")[1] == args.waf]
    if args.attack_type:
        jsonl_files = [p for p in jsonl_files if p.stem.split(".")[2] == args.attack_type]

    if not jsonl_files:
        print("No matching jsonl files found in", INPUT_DIR)
        return

    print(f"Found {len(jsonl_files)} file(s) to re-attack, concurrency={args.concurrency}")

    for jsonl_path in jsonl_files:
        _, waf_name, _ = jsonl_path.stem.split(".")
        if waf_name not in WAF_DOMAINS:
            print(f"Skipping {jsonl_path.name}: unknown WAF name {waf_name!r}")
            continue
        await attack_file(waf_name, jsonl_path, args.concurrency, args.timeout)


def main():
    parser = argparse.ArgumentParser(description="Re-attack already-generated Phase 3 payloads against their target WAF (async, high concurrency).")
    parser.add_argument("--waf", choices=list(WAF_DOMAINS.keys()), default=None, help="Only attack this WAF's output file(s).")
    parser.add_argument("--attack-type", default=None, help="Only attack this attack_type's output file(s).")
    parser.add_argument("--concurrency", type=int, default=30, help="Max concurrent in-flight requests per file.")
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout in seconds.")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
