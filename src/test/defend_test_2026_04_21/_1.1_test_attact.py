

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
import requests
sys.stdout.reconfigure(encoding='utf-8')
from utils import VALID_ATTACK_TYPES, WAF_DVWA_URLS, PHASES, call_api

def api_test_attack(domain: str, payloads: list) -> dict:
    response = call_api("/api/test_attack", json.dumps({
        "domain": domain,
        "check_harmful": False,
        "payloads": payloads,
    }))
    return response.get("data", {}) if response.get("success") else None

input_dir = os.path.join(os.path.dirname(__file__), '1_after_convert')
output_dir = os.path.join(os.path.dirname(__file__), '1.1_after_test_attack')
os.makedirs(output_dir, exist_ok=True)

def main():
    for waf in WAF_DVWA_URLS:
        for attack_type in VALID_ATTACK_TYPES:
            file_name = f"result.{waf}.{attack_type}.PHASE_3.json"
            if not os.path.exists(os.path.join(input_dir, file_name)):
                print(f"Not found {file_name}, skipping...")
                continue
            with open(os.path.join(input_dir, file_name), 'r', encoding='utf-8') as f:
                payload_results = json.load(f)
            print(f"Testing {len(payload_results)} payloads against {waf} for attack type {attack_type}...")
            new_payload_results = api_test_attack(WAF_DVWA_URLS[waf], payload_results)
            for i, r in enumerate(new_payload_results["payloads"]):
                payload_results[i]["status_code"] = r.get("status_code")
                payload_results[i]["is_bypassed"] = r.get("is_bypassed")
                payload_results[i]["is_harmful"] = r.get("is_harmful")
            with open(os.path.join(output_dir, file_name), 'w', encoding='utf-8') as f:
                json.dump(payload_results, f, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    main()
            
