"""
Task 5 - Generate defense rules from Phase 1 + Phase 3 attack results.

For each (waf_name, attack_type, seed), combines that seed's 50 Phase 1
payloads (output_generate_phase1_harmful/phase1.<waf>.<attack_type>.jsonl)
with its 50 Phase 3 payloads (output_generate_phase3_harmful/phase3.<waf>.<attack_type>.jsonl)
- both already carry is_bypassed/is_harmful from _4_harmful.py - and runs
them through the core defend pipeline (defend_pipeline.py, the same one used
by src/test/defend_test_2026_04_21/_2_defend.py) to produce WAF-specific rules.

The defend pipeline only accepts payloads where is_bypassed AND is_harmful
are both True (defend_pipeline._extract_bypassed_payloads); an
(waf, attack_type, seed) group with none of those raises and is skipped with
a warning rather than silently producing an empty result.

Existing rules (for the refine step) are loaded the same way as the old
defend_test_2026_04_21/_2_defend.py: Naxsi -> naxsi_core.rules, ModSecurity
-> REQUEST-941 (xss) / REQUEST-942 (sqli). Cloudflare/AWS have no local rule
file to refine against, so existing_rules is None for them.

Output: output_defend/defend.<waf>.<attack_type>.seed_<seed>.json
"""

import os
import sys
import json
import argparse
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../core")))

from defend_pipeline import (  # noqa: E402
    _1_clustering,
    _2_rag_retrieve,
    _3_generate_rules,
    _4_validate_rules_syntax,
    _5_retry_invalid_rules,
    _6_refine_rules,
)
from models.dtos import PayloadResult  # noqa: E402

from constant import SEEDS, WAF_NAMES, VALID_ATTACK_TYPES  # noqa: E402

HARMFUL_DIRS = {
    1: Path(__file__).parent / "output_generate_phase1_harmful",
    3: Path(__file__).parent / "output_generate_phase3_harmful",
}
OUTPUT_DIR = Path(__file__).parent / "output_defend"
EXISTING_RULES_DIR = Path(__file__).parent / "existing_rules"


def now_str():
    return datetime.now(timezone(timedelta(hours=7))).strftime("%Y-%m-%d %H:%M:%S")


def load_existing_rules(waf_name: str, attack_type: str) -> list[str] | None:
    if waf_name.lower() == "naxsi":
        path = EXISTING_RULES_DIR / "naxsi_core.rules"
    elif waf_name.lower() == "modsecurity":
        if "xss" in attack_type.lower():
            path = EXISTING_RULES_DIR / "REQUEST-941-APPLICATION-ATTACK-XSS.conf"
        elif "sql" in attack_type.lower():
            path = EXISTING_RULES_DIR / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
        else:
            return None
    else:
        return None

    if not path.exists():
        print(f"  [WARN] Existing rules file not found: {path}")
        return None

    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f.readlines() if not line.startswith("#") and line.strip()]


def load_seed_records(jsonl_path: Path, seed: int) -> list[dict]:
    if not jsonl_path.exists():
        return []
    records = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("seed") != seed:
                continue
            attack_result = record.get("attack_result")
            if attack_result is not None:
                # phase1 attack output nests status_code/is_bypassed under attack_result;
                # flatten so downstream code has one consistent shape.
                record = {**record, **attack_result}
            records.append(record)
    return records


def _parse_payload_results(items: list[dict]) -> list[PayloadResult]:
    return [
        PayloadResult(
            payload=item.get("payload", ""),
            technique=item.get("technique", ""),
            attack_type=item.get("attack_type", ""),
            status_code=item.get("status_code"),
            is_bypassed=item.get("is_bypassed"),
            is_harmful=item.get("is_harmful"),
        )
        for item in items
        if isinstance(item, dict)
    ]


def _extract_bypassed_payloads(payload_results: list[PayloadResult]) -> list[str]:
    return [
        str(item.payload).strip()
        for item in payload_results
        if item.is_bypassed and item.is_harmful and str(item.payload).strip()
    ]


def run_defend_pipeline(
    waf_name: str,
    attack_type: str,
    payload_results: list[dict],
    existing_rules: list[str] | None,
    enable_clustering: bool = True,
    enable_rag: bool = True,
    enable_validate_retry: bool = True,
    enable_refine: bool = True,
) -> dict:
    parsed_payload_results = _parse_payload_results(payload_results)
    bypassed_payloads = _extract_bypassed_payloads(parsed_payload_results)

    if not bypassed_payloads:
        raise ValueError(f"No bypassed harmful payloads found for waf={waf_name}, attack_type={attack_type}")

    if enable_clustering:
        clusters = _1_clustering(bypassed_payloads=bypassed_payloads)
    else:
        clusters = [{
            "cluster_id": "Clustering disabled, this is a flat list of payloads",
            "size": len(bypassed_payloads),
            "payloads": bypassed_payloads,
        }]

    if enable_rag:
        rag_result, rag_sources, rag_context = _2_rag_retrieve(
            waf_name=waf_name,
            attack_type=attack_type,
            bypassed_payloads=bypassed_payloads,
        )
    else:
        rag_result = ""
        rag_sources = []
        rag_context = ""

    generated_rules, generation_prompt = _3_generate_rules(
        waf_name=waf_name,
        clusters=clusters,
        rag_context=rag_context,
    )

    if enable_validate_retry:
        valid_rules, invalid_rules = _4_validate_rules_syntax(generated_rules)
        fixed_rules = _5_retry_invalid_rules(
            waf_name=waf_name,
            invalid_rules=invalid_rules,
        ) if invalid_rules else []
    else:
        valid_rules = generated_rules
        invalid_rules = []
        fixed_rules = []

    if enable_refine:
        final_rules = _6_refine_rules(
            waf_name=waf_name,
            valid_rules=[*valid_rules, *fixed_rules],
            existing_rules=existing_rules,
        )
    else:
        final_rules = [*valid_rules, *fixed_rules]

    return {
        "success": True,
        "data": {
            "waf_name": waf_name,
            "attack_type": attack_type,
            "existing_rules_count": len(existing_rules or []),
            "enabled_steps": {
                "clustering": enable_clustering,
                "rag": enable_rag,
                "validate_retry": enable_validate_retry,
                "refine": enable_refine,
            },
            "stats": {
                "total_payloads": len(parsed_payload_results),
                "num_bypassed_payloads": len(bypassed_payloads),
                "num_clusters": len(clusters),
                "rules_generated": len(generated_rules),
                "rules_valid": len(valid_rules),
                "rules_invalid": len(invalid_rules),
                "rules_fixed": len(fixed_rules),
                "rules_refined": len(final_rules),
            },
            "clustered_payloads": clusters,
            "rag_result": rag_result,
            "rag_sources": rag_sources,
            "rag_context": rag_context,
            "generation_prompt": generation_prompt,
            "generated_rules": generated_rules,
            "fixed_rules": fixed_rules,
            "final_rules": final_rules,
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Generate defense rules from combined Phase 1 + Phase 3 attack results, per (waf, attack_type, seed).")
    parser.add_argument("--waf", choices=WAF_NAMES, default=None, help="Only process this WAF name.")
    parser.add_argument("--attack-type", choices=VALID_ATTACK_TYPES, default=None, help="Only process this attack type.")
    parser.add_argument("--seeds", type=int, nargs="+", default=SEEDS, help="Random seeds to process.")
    parser.add_argument("--skip-existing", action="store_true", help="Skip (waf, attack_type, seed) combos whose output file already exists.")
    parser.add_argument("--dry-run", action="store_true", help="Only print the task summary, do not generate.")
    args = parser.parse_args()

    wafs = [args.waf] if args.waf else WAF_NAMES
    attack_types = [args.attack_type] if args.attack_type else VALID_ATTACK_TYPES

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Build the full list of pending (waf, attack_type, seed) combos up front
    # so we can print one task summary before doing any work.
    combos = []  # [(waf_name, attack_type, seed, out_path), ...]
    already_done = 0
    for waf_name in wafs:
        for attack_type in attack_types:
            for seed in args.seeds:
                out_path = OUTPUT_DIR / f"defend.{waf_name}.{attack_type}.seed_{seed}.json"
                if args.skip_existing and out_path.exists():
                    already_done += 1
                    continue
                combos.append((waf_name, attack_type, seed, out_path))

    total_planned = len(wafs) * len(attack_types) * len(args.seeds)

    print("=" * 60)
    print("DEFEND RULE GENERATION - TASK SUMMARY")
    print("=" * 60)
    print(f"WAFs           : {', '.join(wafs)}")
    print(f"Attack types   : {', '.join(attack_types)}")
    print(f"Seeds          : {args.seeds}")
    print(f"Total planned  : {total_planned}")
    print(f"Already done   : {already_done}")
    print(f"To generate    : {len(combos)}")
    print("=" * 60)

    if args.dry_run or not combos:
        return

    total_elapsed = 0.0
    done = 0
    num_combos = len(combos)
    for waf_name, attack_type, seed, out_path in combos:
        phase1_path = HARMFUL_DIRS[1] / f"phase1.{waf_name}.{attack_type}.jsonl"
        phase3_path = HARMFUL_DIRS[3] / f"phase3.{waf_name}.{attack_type}.jsonl"
        existing_rules = load_existing_rules(waf_name, attack_type)

        remaining = num_combos - done
        avg = total_elapsed / done if done > 0 else None
        eta_str = f", avg={avg:.1f}s/combo, eta={timedelta(seconds=int(avg * remaining))}" if avg else ""
        print(f"[{now_str()}] ({done + 1}/{num_combos}) {waf_name}|{attack_type}|seed={seed}{eta_str}")

        phase1_records = load_seed_records(phase1_path, seed)
        phase3_records = load_seed_records(phase3_path, seed)
        combined = phase1_records + phase3_records

        print(f"  phase1={len(phase1_records)} phase3={len(phase3_records)} combined={len(combined)}")

        start = time.perf_counter()
        if not combined:
            print(f"  [WARN] No records found (missing output_generate_phase1_harmful/output_generate_phase3_harmful files?), skipping.")
        else:
            try:
                result = run_defend_pipeline(
                    waf_name=waf_name,
                    attack_type=attack_type,
                    payload_results=combined,
                    existing_rules=existing_rules,
                )
            except ValueError as e:
                print(f"  [WARN] {e}")
            else:
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(result, f, ensure_ascii=False, indent=4)
                print(f"  [{now_str()}] Saved {out_path} ({result['data']['stats']['rules_refined']} final rules)")

        total_elapsed += time.perf_counter() - start
        done += 1


if __name__ == "__main__":
    main()
