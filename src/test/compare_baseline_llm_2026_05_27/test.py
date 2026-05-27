
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    "../../core"
)))

from services import generator
import json

for attack_type in ["xss_reflected", "sqli"]:
    payload_results = []
    for i in range(50):
        print(f"[NO-PEFT] Test {i+1}/50 for {attack_type}...")
        result = generator.generate_payload_baseline("ModSecurity", attack_type)
        payload_results.append(result)
        print(f"\tTechniques:\n\t\t{result.technique}")
        print(f"\tPayload:\n\t\t{result.payload}")

    with open(os.path.abspath(os.path.join(os.path.dirname(__file__), f"baseline_payloads_no_peft_{attack_type}.json")), "w", encoding="utf-8") as f:
        json.dump([result.__dict__ for result in payload_results], f, indent=2)