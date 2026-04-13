

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../gui/backend")))
from datetime import datetime

run_session = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'logs', run_session))
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_dir = r"K:\Workspace\bku\LLM4WAF\src\test\test_gemma2_2b_all_techniques_2026_04_13\logs\2026-04-13_22-14-32"

VALID_ATTACK_TYPES = [
    "xss_dom",
    "xss_reflected", 
    "xss_stored", 
    "sql_injection", 
    "sql_injection_blind"
]

WAF_DVWA_URLS = {
    "ModSecurity":"http://modsec.llmshield.click/",
    "Naxsi":"http://naxsi.llmshield.click/",
    "Cloudflare":"https://llmshield.click/",
    "AWS":"http://aws.llmshield.click/",
}

from dataclasses import asdict
import json
import tqdm
from services.generator import generate_payload_phase1

num_payloads = 50
cp_waf_index = 2
cp_attack_type_index = 1
for waf_name, url in WAF_DVWA_URLS.items():
    waf_index = list(WAF_DVWA_URLS.keys()).index(waf_name)
    for attack_type in VALID_ATTACK_TYPES:
        attack_type_index = VALID_ATTACK_TYPES.index(attack_type)
        if waf_index < cp_waf_index or (waf_index == cp_waf_index and attack_type_index < cp_attack_type_index):
            print(f"Skipping {waf_name} - {attack_type}...")
            continue
        print(f"Generating payloads for {waf_name} - {attack_type}...")
        for i in tqdm.tqdm(range(num_payloads), desc=f"{waf_name}({waf_index+1}/{len(WAF_DVWA_URLS)}) | {attack_type}({attack_type_index+1}/{len(VALID_ATTACK_TYPES)})"):
            payload_result = generate_payload_phase1(waf_name, attack_type)
            with open(os.path.join(log_dir, f"{waf_name}_{attack_type}.txt"), "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(payload_result)) + "\n")
            # break
        # break
    # break