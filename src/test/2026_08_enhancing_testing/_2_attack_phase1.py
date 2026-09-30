"""
Send every generated payload in output/*.jsonl against its target WAF and
record whether it was blocked, using an async httpx client with high
concurrency instead of sequential requests.

Reads output/phase1.<WafName>.<attack_type>.jsonl, adds an "attack_result"
field to each record ({"status_code": int|None, "is_bypassed": bool|None}),
and writes the result to output_attack/phase1.<WafName>.<attack_type>.jsonl.
"""

import argparse
import asyncio
import json
from pathlib import Path

import httpx

from constant import WAF_DOMAINS

HEADERS = {"X-Lab-Key": "llmshield-lab-only"}

INPUT_DIR = Path(__file__).parent / "output_generate_phase1"
OUTPUT_DIR = Path(__file__).parent / "output_attack_phase1"


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


async def attack_file(waf_name: str, jsonl_path: Path, out_path: Path, concurrency: int, timeout: float):
    domain = WAF_DOMAINS[waf_name]
    records = load_records(jsonl_path)

    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [attack_one(client, domain, r["payload"], semaphore) for r in records]
        results = await asyncio.gather(*tasks)

    for record, attack_result in zip(records, results):
        record["attack_result"] = attack_result

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    bypassed = sum(1 for r in results if r["is_bypassed"] == True)
    blocked = sum(1 for r in results if r["is_bypassed"] is False)
    errored = sum(1 for r in results if r["is_bypassed"] is None)
    print(f"[{waf_name}] {jsonl_path.name}: {len(records)} payloads -> bypassed={bypassed} blocked={blocked} error={errored}")


async def main_async(args):
    jsonl_files = sorted(INPUT_DIR.glob("phase1.*.jsonl"))
    if args.waf:
        jsonl_files = [p for p in jsonl_files if p.name.split(".")[1] == args.waf]
    if args.attack_type:
        jsonl_files = [p for p in jsonl_files if p.stem.split(".")[2] == args.attack_type]

    if not jsonl_files:
        print("No matching jsonl files found in", INPUT_DIR)
        return

    print(f"Found {len(jsonl_files)} file(s) to attack, concurrency={args.concurrency}")

    for jsonl_path in jsonl_files:
        _, waf_name, _ = jsonl_path.stem.split(".")
        if waf_name not in WAF_DOMAINS:
            print(f"Skipping {jsonl_path.name}: unknown WAF name {waf_name!r}")
            continue
        out_path = OUTPUT_DIR / jsonl_path.name
        await attack_file(waf_name, jsonl_path, out_path, args.concurrency, args.timeout)


def main():
    parser = argparse.ArgumentParser(description="Attack generated payloads against their target WAF (async, high concurrency).")
    parser.add_argument("--waf", choices=list(WAF_DOMAINS.keys()), default=None, help="Only attack this WAF's output file(s).")
    parser.add_argument("--attack-type", default=None, help="Only attack this attack_type's output file(s).")
    parser.add_argument("--concurrency", type=int, default=30, help="Max concurrent in-flight requests per file.")
    parser.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout in seconds.")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
