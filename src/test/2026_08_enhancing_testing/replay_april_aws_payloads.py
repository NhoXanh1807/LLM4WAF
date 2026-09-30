"""
Re-attack the April 2026 AWS SQLi payloads (test_gemma2_2b_all_techniques_2026_04_13,
gemma2b_pretrained, 50 payloads per phase/attack_type) against the current
aws.llmshield.click, now that the SQLi protection pack is attached.

Reads payload text from the original per-run logs (bypassed/status_code
fields there reflect the old DVWA-session-based attack, not this replay) and
re-sends each payload against the /portal/search endpoint used by
_2_attack_phase1.py / replay_attack_phase3.py, with the same lab header.
"""

import argparse
import asyncio
import json
from pathlib import Path

import httpx

from constant import WAF_DOMAINS

HEADERS = {"X-Lab-Key": "llmshield-lab-only"}

APRIL_LOG_DIR = (
    Path(__file__).parent.parent
    / "test_gemma2_2b_all_techniques_2026_04_13"
    / "logs"
    / "2026-04-13_22-14-32"
)

SOURCE_FILES = {
    "phase1": {
        "sql_injection": APRIL_LOG_DIR / "AWS_sql_injection.txt",
        "sql_injection_blind": APRIL_LOG_DIR / "AWS_sql_injection_blind.txt",
    },
    "phase3": {
        "sql_injection": APRIL_LOG_DIR / "phase3_AWS_sql_injection.txt",
        "sql_injection_blind": APRIL_LOG_DIR / "phase3_AWS_sql_injection_blind.txt",
    },
}

OUTPUT_DIR = Path(__file__).parent / "output_replay_april_aws"


def load_payloads(txt_path: Path) -> list:
    records = []
    with open(txt_path, "r", encoding="utf-8") as f:
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


async def attack_file(phase: str, attack_type: str, src_path: Path, concurrency: int, timeout: float):
    domain = WAF_DOMAINS["AWS"]
    records = load_payloads(src_path)

    semaphore = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [attack_one(client, domain, r["payload"], semaphore) for r in records]
        results = await asyncio.gather(*tasks)

    out_records = []
    for record, attack_result in zip(records, results):
        out_records.append({
            "payload": record["payload"],
            "technique": record.get("technique"),
            "attack_type": attack_type,
            "phase": phase,
            "source": "april_gemma2b_pretrained",
            "april_bypassed": record.get("bypassed"),
            "april_status_code": record.get("status_code"),
            "status_code": attack_result["status_code"],
            "is_bypassed": attack_result["is_bypassed"],
        })
        if "error" in attack_result:
            out_records[-1]["attack_error"] = attack_result["error"]

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / f"{phase}.AWS.{attack_type}.jsonl"
    with open(out_path, "w", encoding="utf-8") as f:
        for record in out_records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    bypassed = sum(1 for r in results if r["is_bypassed"] is True)
    blocked = sum(1 for r in results if r["is_bypassed"] is False)
    errored = sum(1 for r in results if r["is_bypassed"] is None)
    print(f"[{phase}] {attack_type}: {len(records)} payloads -> bypassed={bypassed} blocked={blocked} error={errored}")


async def main_async(args):
    for phase, attack_types in SOURCE_FILES.items():
        if args.phase and phase != args.phase:
            continue
        for attack_type, src_path in attack_types.items():
            if args.attack_type and attack_type != args.attack_type:
                continue
            if not src_path.exists():
                print(f"Skipping {phase}/{attack_type}: {src_path} not found")
                continue
            await attack_file(phase, attack_type, src_path, args.concurrency, args.timeout)


def main():
    parser = argparse.ArgumentParser(description="Re-attack the April AWS SQLi payloads against the current AWS WAF.")
    parser.add_argument("--phase", choices=["phase1", "phase3"], default=None)
    parser.add_argument("--attack-type", choices=["sql_injection", "sql_injection_blind"], default=None)
    parser.add_argument("--concurrency", type=int, default=30)
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
