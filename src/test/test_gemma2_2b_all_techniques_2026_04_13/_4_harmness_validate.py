
import os
import sys

import tqdm
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../gui/backend")))
from datetime import datetime

from services_external import dvwa
from classes import PayloadResult
import json
import time


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
import json
import tqdm
import random

from services import payload_harmness_validator as pv

payload_log_dir = r"K:\Workspace\bku\LLM4WAF\src\test\test_gemma2_2b_all_techniques_2026_04_13\logs\2026-04-13_22-14-32"

cp_waf_index = 0
cp_attack_type_index = 0

output_dir = os.path.join(payload_log_dir, "harmness_hard")
os.makedirs(output_dir, exist_ok=True)

for waf_name, url in WAF_DVWA_URLS.items():
    waf_index = list(WAF_DVWA_URLS.keys()).index(waf_name)
    for attack_type in VALID_ATTACK_TYPES:
        attack_type_index = VALID_ATTACK_TYPES.index(attack_type)
        if waf_index < cp_waf_index or (waf_index == cp_waf_index and attack_type_index < cp_attack_type_index):
            print(f"Skipping {waf_name} - {attack_type}...")
            continue
        phase1_file_path = os.path.join(payload_log_dir, f"result_{waf_name}_{attack_type}.txt")
        phase3_file_path = os.path.join(payload_log_dir, f"phase3_{waf_name}_{attack_type}.txt")
        
        with open(phase1_file_path, 'r', encoding='utf-8') as f:
            phase1_payloads = [PayloadResult(**json.loads(line)) for line in f.readlines()]
        
        with open(phase3_file_path, 'r', encoding='utf-8') as f:
            phase3_payloads = [PayloadResult(**json.loads(line)) for line in f.readlines()]
        
        phases = {
            'PHASE_1':phase1_payloads,
            'PHASE_3':phase3_payloads
        }
        for phase, payloads in phases.items():
            for payload in tqdm.tqdm(payloads, desc=f"{phase} | {waf_name}({waf_index+1}/{len(WAF_DVWA_URLS)}) | {attack_type}({attack_type_index+1}/{len(VALID_ATTACK_TYPES)})"):
                if 'xss' in payload.attack_type:
                    harmness = pv.evaluate_xss_payload(payload.payload, False).__dict__
                    harm = not harmness["is_safe"]
                elif 'sql_injection' in payload.attack_type:
                    harmness = pv.evaluate_sql_payload(payload.payload, False).__dict__
                    harm = len(harmness["harm_queries"]) > 0
                payload_dict = payload.__dict__
                payload_dict["harmness"] = harmness
                payload_dict["harm"] = harm
                
                with open(os.path.join(output_dir, f"harmness_hard_{phase}_{waf_name}_{attack_type}.txt"), "a", encoding="utf-8") as f:
                    f.write(json.dumps(payload_dict) + "\n")