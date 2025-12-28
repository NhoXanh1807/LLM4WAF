
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
from gui.backend.llm_helper.llm import PayloadResult

from gui.backend import utils
from wafw00f.main import WAFW00F



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


def generate_payloads(waf_info, attack_type, num) -> List[PayloadResult]:
    print(f"\n[*] Generating {num} {attack_type} payloads...")
    try:
        payloads = utils.generate_payload_phase1(waf_info, attack_type, num)
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
        session_id = utils.loginDVWA()

        for i, item in enumerate(payloads, 0):
            payload = item.payload
            attack_type = item.attack_type
            result = utils.attack(attack_type, payload, session_id)
            payloads[i].bypassed = not result.blocked
            payloads[i].status_code = result.status_code
            status = "⚠️  BYPASSED" if not result.blocked else "✅ BLOCKED"
            print(f"  [{i}] {status} - {payload}")
        return payloads
    except Exception as e:
        print(f"[-] Failed: {e}")
        return []


def generate_defense(waf_info, payload_results: List[PayloadResult]) -> List[dict]:
    bypassed = [r for r in payload_results if r.bypassed]
    if not bypassed:
        print("\n[+] No bypassed payloads! WAF is secure.")
        return []

    print(f"\n[*] Generating defense rules for {len(bypassed)} bypassed payloads...")
    try:
        result = utils.generate_defend_rules_and_instructions(
            waf_info,
            [r.payload for r in bypassed],
            ["Put the payload into any input on vul web then submit" for r in bypassed]
        )
        content = json.loads(result["choices"][0]["message"]["content"])
        rules = content.get("items", [])

        for i, rule in enumerate(rules, 1):
            print(f"\n{'='*60}\nRule {i}:\n{'='*60}")
            print(rule["rule"])
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
    p_gen.add_argument('-t', '--type', required=True, choices=utils.VALID_ATTACK_TYPES)
    p_gen.add_argument('-n', '--num', type=int, default=5)

    # Attack (full workflow)
    p_attack = subparsers.add_parser('attack')
    p_attack.add_argument('-d', '--domain', required=True)
    p_attack.add_argument('-t', '--type', required=True, choices=utils.VALID_ATTACK_TYPES)
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
        waf = detect_waf(args.domain)
        generate_payloads(waf, args.type, args.num)

    elif args.cmd == 'attack':
        waf = detect_waf(args.domain)
        payloads = generate_payloads(waf, args.type, args.num)
        payloads = test_payloads(payloads, args.type)
        rules = generate_defense(waf, payloads)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump({
                    'domain': args.domain,
                    'waf_info': waf,
                    'results': payloads,
                    'defense_rules': rules
                }, f, indent=2)
            print(f"\n[+] Saved to {args.output}")

    print("\n[+] Done!\n")


if __name__ == '__main__':
    main()
