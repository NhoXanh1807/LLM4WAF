
#!/usr/bin/env python3
"""
LLMShield CLI - Command Line Interface for WAF Testing
"""

import argparse
import sys
import json
from pathlib import Path
from typing import List

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from gui.backend.services.generator import PayloadResult, generate_payload_phase1, generate_payload_phase3, generate_defend_rules_and_instructions
from gui.backend.services_external.dvwa import loginDVWA, attack, VALID_ATTACK_TYPES
from wafw00f.main import WAFW00F
from defense.defense_pipeline import DefensePipeline
from validator_syntax_rule.base import WAFType



def print_banner():
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    colors = [
        "\033[32m",  # xanh lá
        "\033[36m",  # cyan
        "\033[34m",  # xanh dương
        "\033[35m",  # tím
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


def detect_waf(domain) -> str:
    print(f"\n[*] Detecting WAF on {domain}...")
    try:
        w = WAFW00F(domain)
        waf_info = w.identwaf()
        waf_name = waf_info[0][0] if len(waf_info[0]) > 0 else None
        print(f"[+] WAF: {json.dumps(waf_info, indent=2)}")
        return waf_name
    except Exception as e:
        print(f"[-] Failed: {e}")
        return None


def generate_payloads(waf_name, attack_type, num) -> List[PayloadResult]:
    print(f"\n[*] Generating {num} {attack_type} payloads...")
    try:
        payloads = generate_payload_phase1(waf_name, attack_type, num)
        print(f"[+] Generated {len(payloads)} payloads")
        for i, p in enumerate(payloads, 1):
            print(f"\n  [{i}] {p.payload}")
        return payloads
    except Exception as e:
        print(f"[-] Failed: {e}")
        return []


def test_payloads(payloads: List[PayloadResult], attack_type) -> List[PayloadResult]:
    print(f"\n[*] Testing payloads...")

    try:
        session_id = loginDVWA()

        for i, item in enumerate(payloads, 0):
            payload = item.payload
            attack_type = item.attack_type
            result = attack(attack_type, payload, session_id)
            payloads[i].bypassed = not result.blocked
            payloads[i].status_code = result.status_code
            status = "⚠️  BYPASSED" if not result.blocked else "✅ BLOCKED"
            print(f"  [{i}] {status} - {payload}")
        return payloads
    except Exception as e:
        print(f"[-] Failed: {e}")
        return []


_WAF_NAME_MAP = {
    "modsecurity": WAFType.MODSECURITY,
    "cloudflare": WAFType.CLOUDFLARE,
    "aws": WAFType.AWS_WAF,
    "naxsi": WAFType.NAXSI,
}

def _map_waf_type(waf_name: str) -> WAFType:
    name_lower = (waf_name or "").lower()
    for key, waf_type in _WAF_NAME_MAP.items():
        if key in name_lower:
            return waf_type
    return WAFType.MODSECURITY

_pipeline: DefensePipeline = None

def _get_pipeline() -> DefensePipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = DefensePipeline(enable_rag=True, enable_gemini=True, enable_clustering=True)
    return _pipeline


def generate_defense(waf_name, payload_results: List[PayloadResult]) -> List[dict]:
    bypassed = [r for r in payload_results if r.bypassed]
    if not bypassed:
        print("\n[+] No bypassed payloads! WAF is secure.")
        return []

    print(f"\n[*] Running defense pipeline for {len(bypassed)} bypassed payloads...")
    try:
        pipeline_result = _get_pipeline().generate_defense_rules(
            bypassed_payloads=[r.payload for r in bypassed],
            waf_name=waf_name,
            waf_type=_map_waf_type(waf_name),
        )

        rules = [r.to_dict() for r in pipeline_result.final_rules]
        stats = pipeline_result.to_dict()["stats"]
        print(f"[+] Pipeline stats: {stats}")

        for i, rule in enumerate(rules, 1):
            print(f"\n{'='*60}\nRule {i} [{rule.get('waf_type', '')}]:\n{'='*60}")
            print(rule["rule"])
            if rule.get("refinement_notes"):
                print(f"\nRefinement: {rule['refinement_notes']}")
            print(f"\nImplementation:\n{rule['instructions']}\n")

        return rules
    except Exception as e:
        print(f"[-] Failed: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description='LLMShield CLI')
    subparsers = parser.add_subparsers(dest='cmd')

    # Detect
    p_detect = subparsers.add_parser('detect')
    p_detect.add_argument('-d', '--domain', required=True)

    # Generate
    p_gen = subparsers.add_parser('generate')
    p_gen.add_argument('-d', '--domain', required=True)
    p_gen.add_argument('-t', '--type', required=True, choices=VALID_ATTACK_TYPES)
    p_gen.add_argument('-n', '--num', type=int, default=5)

    # Attack (full workflow)
    p_attack = subparsers.add_parser('attack')
    p_attack.add_argument('-d', '--domain', required=True)
    p_attack.add_argument('-t', '--type', required=True, choices=VALID_ATTACK_TYPES)
    p_attack.add_argument('-n', '--num', type=int, default=5)
    p_attack.add_argument('-o', '--output', help='Output JSON file')

    args = parser.parse_args()

    if not args.cmd:
        parser.print_help()
        return

    print_banner()

    # Ensure https
    if hasattr(args, 'domain'):
        if not args.domain.startswith('http'):
            args.domain = f'https://{args.domain}'

    if args.cmd == 'detect':
        detect_waf(args.domain)

    elif args.cmd == 'generate':
        waf_name = detect_waf(args.domain)
        generate_payloads(waf_name, args.type, args.num)

    elif args.cmd == 'attack':
        waf_name = detect_waf(args.domain)
        payloads = generate_payloads(waf_name, args.type, args.num)
        payloads = test_payloads(payloads, args.type)
        rules = generate_defense(waf_name, payloads)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump({
                    'domain': args.domain,
                    'waf_name': waf_name,
                    'results': [vars(p) if hasattr(p, '__dict__') else p for p in payloads],
                    'defense_rules': rules,
                }, f, indent=2, default=str)
            print(f"\n[+] Saved to {args.output}")

    print("\n[+] Done!\n")


if __name__ == '__main__':
    main()
