

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../gui/backend")))
from datetime import datetime

log_dir = r""

VALID_ATTACK_TYPES = [
    "xss_dom",
    "xss_reflected", 
    "xss_stored", 
    "sql_injection", 
    "sql_injection_blind"
]

WAF_DVWA_URLS = {
    # "ModSecurity":"http://modsec.llmshield.click/",
    # "Naxsi":"http://naxsi.llmshield.click/",
    "Cloudflare":"https://llmshield.click/",
    # "AWS":"http://aws.llmshield.click/",
}

from dataclasses import asdict
import json
import tqdm
import requests
from services.generator import generate_payload_phase1

BACKEND = "http://127.0.0.1:5000"


def call_api(path, body) -> dict:
    try:
        response = requests.post(BACKEND + path, data=body)
        return {"success": True, "data": response.json()}
    except requests.HTTPError as exc:
        error_body = exc.response.text
        try:
            return {"success": False, "error": json.loads(error_body)}
        except json.JSONDecodeError:
            return {"success": False, "error": error_body}
    except requests.RequestException as exc:
        return {"success": False, "error": "Request error: " + str(exc)}
    except Exception as exc:
        return {"success": False, "error": "Unexpected error: " + str(exc)}

def api_test_attack(domain: str, payloads: list) -> dict:
    response = call_api("/api/test_attack", json.dumps({
        "domain": domain,
        "payloads": payloads,
    }))
    return response.get("data", {}) if response.get("success") else None

num_payloads = 50
cp_waf_index = 0
cp_attack_type_index = 0
for waf_name, url in WAF_DVWA_URLS.items():
    waf_index = list(WAF_DVWA_URLS.keys()).index(waf_name)
    for attack_type in VALID_ATTACK_TYPES:
        attack_type_index = VALID_ATTACK_TYPES.index(attack_type)
        if waf_index < cp_waf_index or (waf_index == cp_waf_index and attack_type_index < cp_attack_type_index):
            print(f"Skipping {waf_name} - {attack_type}...")
            continue
        print(f"Generating payloads for {waf_name} - {attack_type}...")
        payloads = []
        for i in tqdm.tqdm(range(num_payloads), desc=f"{waf_name}({waf_index+1}/{len(WAF_DVWA_URLS)}) | {attack_type}({attack_type_index+1}/{len(VALID_ATTACK_TYPES)})"):
            payload_result = generate_payload_phase1(waf_name, attack_type)
            payloads.append(payload_result)
            
            with open(os.path.join(log_dir, f"{waf_name}_{attack_type}_phase1_payloads.txt"), "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(payload_result)) + "\n")
        
        payload_results = api_test_attack(url, [p.__dict__ for p in payloads])
        with open(os.path.join(log_dir, f"{waf_name}_{attack_type}_phase1_results.json"), "w", encoding="utf-8") as f:
            json.dump(payload_results, f, ensure_ascii=False, indent=4)
            
        # break
    # break