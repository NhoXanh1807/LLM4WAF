
#!/usr/bin/env python3
"""
LLMShield CLI - Command Line Interface for WAF Testing
"""

import argparse
import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

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


def detect_waf(domain):
    print(f"\n[*] Detecting WAF on {domain}...")
    try:
        w = WAFW00F(domain)
        waf_info = w.identwaf()
        print(f"[+] WAF: {json.dumps(waf_info, indent=2)}")
        return waf_info
    except Exception as e:
        print(f"[-] Failed: {e}")
        return {"detected": False}


def generate_payloads(waf_info, attack_type, num):
    print(f"\n[*] Generating {num} {attack_type} payloads...")
    try:
        result = utils.generate_payloads_from_domain_waf_info(waf_info, attack_type, num)
        content = json.loads(result["choices"][0]["message"]["content"])
        payloads = content.get("items", [])
        print(f"[+] Generated {len(payloads)} payloads")
        for i, p in enumerate(payloads, 1):
            print(f"\n  [{i}] {p['payload']}")
        return payloads
    except Exception as e:
        print(f"[-] Failed: {e}")
        return []


def test_payloads(payloads, attack_type):
    print(f"\n[*] Testing payloads...")
    attack_funcs = {
        "xss_dom": utils.attack_xss_dom,
        "xss_reflected": utils.attack_xss_reflected,
        "xss_stored": utils.attack_xss_stored,
        "sql_injection": utils.attack_sql_injection,
        "sql_injection_blind": utils.attack_sql_injection_blind,
    }

    try:
        session_id = utils.loginDVWA()
        func = attack_funcs.get(attack_type)
        results = []

        for i, item in enumerate(payloads, 1):
            payload = item["payload"]
            result = func(payload, session_id)
            bypassed = not result["blocked"]
            status = "⚠️  BYPASSED" if bypassed else "✅ BLOCKED"
            print(f"  [{i}] {status} - {payload}")
            results.append({**item, "bypassed": bypassed, "status_code": result["status_code"]})

        return results
    except Exception as e:
        print(f"[-] Failed: {e}")
        return []


def generate_defense(waf_info, results):
    bypassed = [r for r in results if r.get("bypassed")]
    if not bypassed:
        print("\n[+] No bypassed payloads! WAF is secure.")
        return []

    print(f"\n[*] Generating defense rules for {len(bypassed)} bypassed payloads...")
    try:
        result = utils.generate_defend_rules_and_instructions(
            waf_info,
            [r["payload"] for r in bypassed],
            [r["instruction"] for r in bypassed]
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
    p_gen.add_argument('-t', '--type', required=True,
                       choices=['xss_dom', 'xss_reflected', 'xss_stored', 'sql_injection', 'sql_injection_blind'])
    p_gen.add_argument('-n', '--num', type=int, default=5)

    # Attack (full workflow)
    p_attack = subparsers.add_parser('attack')
    p_attack.add_argument('-d', '--domain', required=True)
    p_attack.add_argument('-t', '--type', required=True,
                          choices=['xss_dom', 'xss_reflected', 'xss_stored', 'sql_injection', 'sql_injection_blind'])
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
        results = test_payloads(payloads, args.type)
        rules = generate_defense(waf, results)

        if args.output:
            with open(args.output, 'w') as f:
                json.dump({
                    'domain': args.domain,
                    'waf_info': waf,
                    'results': results,
                    'defense_rules': rules
                }, f, indent=2)
            print(f"\n[+] Saved to {args.output}")

    print("\n[+] Done!\n")


if __name__ == '__main__':
    main()
