
#!/usr/bin/env python3
"""
LLM4WAF CLI - Command Line Interface aligned with the Flask backend.

This CLI mirrors the main backend endpoints:
    - /api/detect_waf
    - /api/generate_payload
    - /api/test_attack
    - /api/defend

It also provides a workflow command that runs the full sequence:
detect -> generate -> test -> defend.
"""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable, List, Optional


def _bootstrap_paths() -> None:
    current_file = Path(__file__).resolve()
    src_dir = current_file.parent.parent
    project_root = src_dir.parent
    backend_dir = src_dir / "gui" / "backend"

    for path in (str(src_dir), str(project_root), str(backend_dir)):
        if path not in sys.path:
            sys.path.insert(0, path)


_bootstrap_paths()

from wafw00f.main import WAFW00F

from classes import PayloadResult
from config.settings import DEFAULT_NUM_PAYLOADS
from defense.defense_pipeline import DefensePipeline
from services import payload_harmness_validator as harmfulness
from services.generator import generate_payloads_phase1, generate_payloads_phase3
from services_external import dvwa
from validator_syntax_rule.base import WAFType


def print_banner():
    RESET = "\033[0m"
    BOLD = "\033[1m"
    colors = [
        "\033[32m",
        "\033[36m",
        "\033[34m",
        "\033[35m",
    ]

    banner = r"""
 ___       ___       _____ ______   ________  ___  ___  ___  _______   ___       ________
|\  \     |\  \     |\   _ \  _   \|\   ____\|\  \|\  \|\  \|\  ___ \ |\  \     |\   ___ \
\ \  \    \ \  \    \ \  \\\__\ \  \ \  \___|\ \  \\\  \ \  \ \   __/|\ \  \    \ \  \_|\ \
 \ \  \    \ \  \    \ \  \\|__| \  \ \_____  \ \   __  \ \  \ \  \_|/_\ \  \    \ \  \ \\ \
  \ \  \____\ \  \____\ \  \    \ \  \|____|\  \ \  \ \  \ \  \ \  \_|\ \ \  \____\ \  \_\\ \
   \ \_______\ \_______\ \__\    \ \__\____\_\  \ \__\ \__\ \__\ \_______\ \_______\ \_______\
    \|_______|\|_______|\|__|     \|__|\_________\|__|\|__|\|__|\|_______|\|_______|\|_______|
                                      \|_________|
"""
    for i, line in enumerate(banner.splitlines()):
        c = colors[i % len(colors)]
        print(BOLD + c + line + RESET)


CLI_DESCRIPTION = """
LLM4WAF command line interface.

The commands mirror the Flask backend so you can run the same workflow without
starting the web server. JSON inputs and outputs are shaped to match app.py.
""".strip()


CLI_EPILOG = """
Examples:
  python src/cli/main.py detect-waf --domain http://localhost
  python src/cli/main.py generate-payload --waf-name ModSecurity --attack-type xss_reflected --num-payloads 5 --output payloads.json
  python src/cli/main.py generate --domain http://localhost --type sql_injection --num 3
  python src/cli/main.py test-attack --domain http://localhost --payloads-file payloads.json --output tested.json
  python src/cli/main.py defend --waf-name ModSecurity --attack-type xss_reflected --payloads-file tested.json --existing-rules-file rules.txt --output defend.json
  python src/cli/main.py workflow --domain http://localhost --attack-type xss_reflected --num-payloads 5 --output result.json

Input file conventions:
  - payload files can be a JSON array of payload objects or an object containing
    one of these keys: payloads, results, payloads_history.
  - existing rules can be TXT, JSON array, JSON object with rules, or a JSON
    string containing those structures.
""".strip()


_WAF_NAME_MAP = {
    "modsecurity": WAFType.MODSECURITY,
    "cloudflare": WAFType.CLOUDFLARE,
    "aws": WAFType.AWS_WAF,
    "naxsi": WAFType.NAXSI,
}

_pipeline: Optional[DefensePipeline] = None


def _get_pipeline() -> DefensePipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = DefensePipeline(
            enable_rag=True,
            enable_gemini=True,
            enable_clustering=True,
        )
    return _pipeline


def _normalize_domain(domain: str) -> str:
    if not domain.startswith("http://") and not domain.startswith("https://"):
        return "http://" + domain
    return domain


def _map_waf_type(waf_name: str) -> WAFType:
    name_lower = (waf_name or "").lower()
    for key, waf_type in _WAF_NAME_MAP.items():
        if key in name_lower:
            return waf_type
    return WAFType.MODSECURITY


def _parse_existing_rules(raw: object) -> list[str]:
    if not raw:
        return []

    if isinstance(raw, list):
        rules = []
        for item in raw:
            if isinstance(item, str):
                rules.append(item.strip())
            elif isinstance(item, dict):
                rule = item.get("rule", "")
                if rule:
                    rules.append(rule.strip())
        return [rule for rule in rules if rule]

    if isinstance(raw, dict):
        if "rules" in raw:
            return _parse_existing_rules(raw.get("rules"))
        if "existing_rules" in raw:
            return _parse_existing_rules(raw.get("existing_rules"))
        if "rule" in raw:
            return _parse_existing_rules([raw])
        return []

    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return []
        if stripped.startswith("[") or stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
                return _parse_existing_rules(parsed)
            except Exception:
                pass
        return [
            line.strip()
            for line in stripped.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    return []


def _read_text_file(file_path: str) -> str:
    return Path(file_path).read_text(encoding="utf-8")


def _read_json_file(file_path: str) -> Any:
    return json.loads(_read_text_file(file_path))


def _payload_result_from_dict(item: dict[str, Any]) -> PayloadResult:
    return PayloadResult(
        payload=item.get("payload"),
        technique=item.get("technique"),
        attack_type=item.get("attack_type"),
        status_code=item.get("status_code"),
        is_bypassed=item.get("is_bypassed"),
        is_harmful=item.get("is_harmful"),
    )


def _payload_result_to_dict(item: PayloadResult) -> dict[str, Any]:
    return asdict(item)


def _extract_payload_items(raw: Any) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        for key in ("payloads", "results", "payloads_history"):
            value = raw.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    raise ValueError("Unsupported payload file format")


def _load_payloads(file_path: str) -> list[PayloadResult]:
    data = _read_json_file(file_path)
    return [_payload_result_from_dict(item) for item in _extract_payload_items(data)]


def _build_payloads_from_args(payload_values: Optional[list[str]], attack_type: Optional[str]) -> list[PayloadResult]:
    if not payload_values:
        return []
    if not attack_type:
        raise ValueError("--attack-type is required when using --payload")
    return [
        PayloadResult(payload=value, technique="manual", attack_type=attack_type)
        for value in payload_values
    ]


def _write_json_output(data: dict[str, Any], output_path: Optional[str]) -> None:
    if not output_path:
        return
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] Saved JSON output to {output_file}")


def _print_json_if_requested(data: dict[str, Any], enabled: bool) -> None:
    if enabled:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def _print_payload_summary(payloads: Iterable[PayloadResult]) -> None:
    payload_list = list(payloads)
    print(f"[+] Payload count: {len(payload_list)}")
    for index, payload in enumerate(payload_list, start=1):
        status_parts = []
        if payload.is_bypassed is not None:
            status_parts.append("BYPASSED" if payload.is_bypassed else "BLOCKED")
        if payload.is_harmful is not None:
            status_parts.append("HARMFUL" if payload.is_harmful else "SAFE")
        if payload.status_code is not None:
            status_parts.append(f"HTTP {payload.status_code}")
        status_suffix = f" [{' | '.join(status_parts)}]" if status_parts else ""
        print(f"  [{index}] {payload.payload}{status_suffix}")


def _load_existing_rules_input(file_path: Optional[str], inline_rules: Optional[str]) -> list[str]:
    if file_path:
        return _parse_existing_rules(_read_text_file(file_path))
    if inline_rules:
        return _parse_existing_rules(inline_rules)
    return []


def detect_waf(domain: str) -> dict[str, Any]:
    domain = _normalize_domain(domain)
    print(f"\n[*] Detecting WAF on {domain}...")
    w = WAFW00F(domain)
    waf_info = w.identwaf()
    waf_name = waf_info[0][0] if len(waf_info[0]) > 0 else "NO_WAF_INFORMATION"
    print(f"[+] WAF detected: {waf_name}")
    return {
        "domain": domain,
        "waf_name": waf_name,
        "waf_info": waf_info,
    }


def generate_payloads(
    waf_name: str,
    attack_type: str,
    num_payloads: int,
    payloads_history: Optional[list[PayloadResult]] = None,
) -> dict[str, Any]:
    if attack_type not in dvwa.VALID_ATTACK_TYPES:
        raise ValueError(f"'attack_type' must be in {dvwa.VALID_ATTACK_TYPES}")

    payloads_history = payloads_history or []
    print(
        f"\n[*] Generating payloads for waf={waf_name}, attack_type={attack_type}, "
        f"num_payloads={num_payloads}, history={len(payloads_history)}"
    )

    if payloads_history:
        payloads = generate_payloads_phase3(
            waf_name,
            attack_type,
            num_of_payloads=num_payloads,
            probe_history=payloads_history,
        )
    else:
        payloads = generate_payloads_phase1(
            waf_name,
            attack_type,
            num_of_payloads=num_payloads,
        )

    _print_payload_summary(payloads)
    return {
        "waf_name": waf_name,
        "attack_type": attack_type,
        "payloads": [_payload_result_to_dict(item) for item in payloads],
    }


def test_attack(
    domain: str,
    payloads: list[PayloadResult],
    check_harmful: bool = True,
) -> dict[str, Any]:
    if not domain:
        raise ValueError("Missing domain")

    domain = _normalize_domain(domain)
    print(f"\n[*] Logging in to DVWA at {domain}...")
    session_id = dvwa.loginDVWA(base_url=domain)

    for index, item in enumerate(payloads, start=1):
        payload = item.payload
        attack_type = item.attack_type

        if check_harmful and payload and attack_type:
            if "xss" in attack_type.lower():
                harmfulness_result = harmfulness.evaluate_xss_payload(payload)
                if harmfulness_result:
                    item.is_harmful = not harmfulness_result.is_safe
            elif "sql" in attack_type.lower():
                harmfulness_result = harmfulness.evaluate_sql_payload(payload)
                if harmfulness_result:
                    item.is_harmful = len(harmfulness_result.harm_queries) > 0

        attack_func = dvwa.DVWA_ATTACK_FUNC.get(attack_type)
        print(f"[DVWA-Check] {index}/{len(payloads)} : {item.payload}")

        if attack_func and payload:
            result = dvwa.attack(attack_type, payload, session_id, base_url=domain)
            item.is_bypassed = None if result.blocked is None else not result.blocked
            item.status_code = result.status_code
            print(
                f"    {('BYPASSED' if item.is_bypassed else 'BLOCKED' if item.is_bypassed is not None else 'UNKNOWN')}"
                f" code({item.status_code})"
            )
        else:
            item.is_bypassed = None
            item.status_code = None
            print("    SKIPPED (missing attack_func or payload)")

    _print_payload_summary(payloads)
    return {
        "payloads": [_payload_result_to_dict(item) for item in payloads],
    }


def defend(
    waf_name: str,
    payloads: list[PayloadResult],
    attack_type: str,
    existing_rules_raw: Optional[object] = None,
) -> dict[str, Any]:
    if not waf_name:
        raise ValueError("Missing 'waf_name' field")

    existing_rules = _parse_existing_rules(existing_rules_raw)
    if existing_rules:
        print(
            f"\n[*] Advanced Defense Mode enabled: {len(existing_rules)} existing rule(s) loaded"
        )

    bypassed_payloads = [
        payload.payload
        for payload in payloads
        if payload.is_bypassed and payload.is_harmful
    ]

    print(
        f"\n[*] Running defense pipeline with {len(bypassed_payloads)} harmful bypassed payload(s)..."
    )
    pipeline_result = _get_pipeline().generate_defense_rules(
        bypassed_payloads=bypassed_payloads,
        waf_name=waf_name,
        waf_type=_map_waf_type(waf_name),
        existing_rules=existing_rules if existing_rules else None,
        attack_type=attack_type,
    )

    result = {
        "waf_name": waf_name,
        "clustered_payloads": [cluster.to_dict() for cluster in pipeline_result.cluster_info],
        "rag_sources": pipeline_result.rag_sources,
        "generated_rules": [rule.to_dict() for rule in pipeline_result.generated_rules],
        "advanced_defense": bool(existing_rules),
        "existing_rules_count": len(existing_rules),
        "final_rules": [rule.to_dict() for rule in pipeline_result.final_rules],
        "stats": pipeline_result.to_dict()["stats"],
        "success": pipeline_result.success,
        "stage": pipeline_result.stage.value,
        "error_message": pipeline_result.error_message,
    }

    print(f"[+] Final rules: {len(result['final_rules'])}")
    for index, rule in enumerate(result["final_rules"], start=1):
        print(f"\n{'=' * 60}\nRule {index} [{rule.get('waf_type', '')}]\n{'=' * 60}")
        print(rule.get("rule", ""))
        if rule.get("refinement_notes"):
            print(f"\nRefinement: {rule['refinement_notes']}")
        instructions = rule.get("instructions")
        if instructions:
            print(f"\nImplementation:\n{instructions}")

    return result


def run_workflow(
    domain: str,
    attack_type: str,
    num_payloads: int,
    existing_rules_raw: Optional[object] = None,
) -> dict[str, Any]:
    detect_result = detect_waf(domain)
    generate_result = generate_payloads(
        waf_name=detect_result["waf_name"],
        attack_type=attack_type,
        num_payloads=num_payloads,
    )
    tested_payloads = [
        _payload_result_from_dict(item) for item in generate_result["payloads"]
    ]
    test_result = test_attack(domain=domain, payloads=tested_payloads)
    defended_payloads = [_payload_result_from_dict(item) for item in test_result["payloads"]]
    defend_result = defend(
        waf_name=detect_result["waf_name"],
        payloads=defended_payloads,
        attack_type=attack_type,
        existing_rules_raw=existing_rules_raw,
    )
    return {
        "domain": detect_result["domain"],
        "waf_name": detect_result["waf_name"],
        "detect": detect_result,
        "generate": generate_result,
        "test": test_result,
        "defend": defend_result,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=CLI_DESCRIPTION,
        epilog=CLI_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    detect_parser = subparsers.add_parser(
        "detect-waf",
        aliases=["detect"],
        help="Detect the WAF for a target domain.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    detect_parser.add_argument("--domain", "-d", required=True, help="Target domain or base URL.")
    detect_parser.add_argument("--output", "-o", help="Write the JSON response to a file.")
    detect_parser.add_argument("--json", action="store_true", help="Print JSON response to stdout.")

    generate_parser = subparsers.add_parser(
        "generate-payload",
        aliases=["generate"],
        help="Generate payloads like /api/generate_payload.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    generate_parser.add_argument("--waf-name", help="Detected WAF name. Optional when --domain is provided.")
    generate_parser.add_argument("--domain", "-d", help="Optional domain. If set and --waf-name is missing, WAF will be detected first.")
    generate_parser.add_argument("--attack-type", "--type", "-t", required=True, choices=dvwa.VALID_ATTACK_TYPES, help="Attack type.")
    generate_parser.add_argument("--num-payloads", "--num", "-n", type=int, default=DEFAULT_NUM_PAYLOADS, help="Number of payloads to generate.")
    generate_parser.add_argument("--payloads-history-file", help="JSON file containing payload history for adaptive generation.")
    generate_parser.add_argument("--output", "-o", help="Write the JSON response to a file.")
    generate_parser.add_argument("--json", action="store_true", help="Print JSON response to stdout.")

    test_parser = subparsers.add_parser(
        "test-attack",
        aliases=["test"],
        help="Test payloads against DVWA like /api/test_attack.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    test_parser.add_argument("--domain", "-d", required=True, help="DVWA base URL or domain.")
    test_parser.add_argument("--payloads-file", help="JSON file containing payload objects.")
    test_parser.add_argument("--payload", action="append", dest="payload_values", help="Manual payload value. Can be repeated.")
    test_parser.add_argument("--attack-type", "--type", "-t", choices=dvwa.VALID_ATTACK_TYPES, help="Required with --payload.")
    test_parser.add_argument("--skip-harmful-check", action="store_true", help="Disable harmfulness validation before testing.")
    test_parser.add_argument("--output", "-o", help="Write the JSON response to a file.")
    test_parser.add_argument("--json", action="store_true", help="Print JSON response to stdout.")

    defend_parser = subparsers.add_parser(
        "defend",
        help="Generate defense rules like /api/defend.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    defend_parser.add_argument("--waf-name", required=True, help="Detected WAF name.")
    defend_parser.add_argument("--attack-type", "--type", "-t", default="unknown", help="Attack type for the defense pipeline.")
    defend_parser.add_argument("--payloads-file", required=True, help="JSON file containing payload objects, typically from test-attack or workflow output.")
    defend_parser.add_argument("--existing-rules-file", help="TXT or JSON file with existing rules.")
    defend_parser.add_argument("--existing-rules", help="Inline existing rules as text or JSON.")
    defend_parser.add_argument("--output", "-o", help="Write the JSON response to a file.")
    defend_parser.add_argument("--json", action="store_true", help="Print JSON response to stdout.")

    workflow_parser = subparsers.add_parser(
        "workflow",
        aliases=["attack", "run"],
        help="Run detect -> generate -> test -> defend in one command.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    workflow_parser.add_argument("--domain", "-d", required=True, help="Target domain or DVWA base URL.")
    workflow_parser.add_argument("--attack-type", "--type", "-t", required=True, choices=dvwa.VALID_ATTACK_TYPES, help="Attack type.")
    workflow_parser.add_argument("--num-payloads", "--num", "-n", type=int, default=DEFAULT_NUM_PAYLOADS, help="Number of payloads to generate.")
    workflow_parser.add_argument("--existing-rules-file", help="TXT or JSON file with existing rules for advanced defense mode.")
    workflow_parser.add_argument("--existing-rules", help="Inline existing rules as text or JSON.")
    workflow_parser.add_argument("--output", "-o", help="Write the JSON response to a file.")
    workflow_parser.add_argument("--json", action="store_true", help="Print JSON response to stdout.")

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        return 1

    print_banner()

    try:
        if args.command in {"detect-waf", "detect"}:
            result = detect_waf(args.domain)

        elif args.command in {"generate-payload", "generate"}:
            waf_name = args.waf_name
            if not waf_name:
                if not args.domain:
                    raise ValueError("Provide either --waf-name or --domain")
                waf_name = detect_waf(args.domain)["waf_name"]

            payload_history = _load_payloads(args.payloads_history_file) if args.payloads_history_file else []
            result = generate_payloads(
                waf_name=waf_name,
                attack_type=args.attack_type,
                num_payloads=args.num_payloads,
                payloads_history=payload_history,
            )

        elif args.command in {"test-attack", "test"}:
            payloads = []
            if args.payloads_file:
                payloads.extend(_load_payloads(args.payloads_file))
            payloads.extend(_build_payloads_from_args(args.payload_values, args.attack_type))
            if not payloads:
                raise ValueError("Provide --payloads-file or at least one --payload")

            result = test_attack(
                domain=args.domain,
                payloads=payloads,
                check_harmful=not args.skip_harmful_check,
            )

        elif args.command == "defend":
            payloads = _load_payloads(args.payloads_file)
            existing_rules = _load_existing_rules_input(args.existing_rules_file, args.existing_rules)
            result = defend(
                waf_name=args.waf_name,
                payloads=payloads,
                attack_type=args.attack_type,
                existing_rules_raw=existing_rules,
            )

        elif args.command in {"workflow", "attack", "run"}:
            existing_rules = _load_existing_rules_input(args.existing_rules_file, args.existing_rules)
            result = run_workflow(
                domain=args.domain,
                attack_type=args.attack_type,
                num_payloads=args.num_payloads,
                existing_rules_raw=existing_rules,
            )

        else:
            raise ValueError(f"Unsupported command: {args.command}")

        _write_json_output(result, getattr(args, "output", None))
        _print_json_if_requested(result, getattr(args, "json", False))
        print("\n[+] Done!\n")
        return 0

    except Exception as exc:
        print(f"\n[-] Error: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
