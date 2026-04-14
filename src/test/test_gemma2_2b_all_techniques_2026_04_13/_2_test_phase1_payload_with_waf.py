


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

SESSION_IDS = {}

payload_log_dir = r""

for waf_name, url in WAF_DVWA_URLS.items():
    waf_index = list(WAF_DVWA_URLS.keys()).index(waf_name)
    if waf_name not in SESSION_IDS:
        print(f"Logging in to DVWA {waf_name} at {url}...")
        SESSION_IDS[waf_name] = dvwa.loginDVWA(WAF_DVWA_URLS[waf_name])
    for attack_type in VALID_ATTACK_TYPES:
        attack_type_index = VALID_ATTACK_TYPES.index(attack_type)
        payloads_file_path = os.path.join(payload_log_dir, f"{waf_name}_{attack_type}.txt")
        
        print(f"Waiting for {payloads_file_path}...")
        lines = []
        while not os.path.exists(payloads_file_path) or len(lines) < 50:
            if os.path.exists(payloads_file_path):
                with open(payloads_file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            time.sleep(5)
        
        for line in tqdm.tqdm(lines, desc=f"{waf_name}({waf_index+1}/{len(WAF_DVWA_URLS)}) | {attack_type}({attack_type_index+1}/{len(VALID_ATTACK_TYPES)})"):
            payload_result = PayloadResult(**json.loads(line))
            attack_result = dvwa.attack(
                attack_type, 
                payload_result.payload, 
                SESSION_IDS[waf_name],
                WAF_DVWA_URLS[waf_name]
            )
            payload_result.bypassed = attack_result.blocked == False
            payload_result.status_code = attack_result.status_code
            
            with open(os.path.join(payload_log_dir, f"result_{waf_name}_{attack_type}.txt"), "a", encoding="utf-8") as f:
                f.write(json.dumps(payload_result.__dict__) + "\n")
