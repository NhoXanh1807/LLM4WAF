
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

import json
import tqdm
import random

from services.generator import generate_payload_phase3
from services_external import dvwa

payload_log_dir = r""

num_payloads = 50

for waf_name, url in WAF_DVWA_URLS.items():
    waf_index = list(WAF_DVWA_URLS.keys()).index(waf_name)
    if waf_name not in SESSION_IDS:
        print(f"Logging in to DVWA {waf_name} at {url}...")
        SESSION_IDS[waf_name] = dvwa.loginDVWA(WAF_DVWA_URLS[waf_name])
    for attack_type in VALID_ATTACK_TYPES:
        attack_type_index = VALID_ATTACK_TYPES.index(attack_type)
        attack_result_file_path = os.path.join(payload_log_dir, f"result_{waf_name}_{attack_type}.txt")
        print(f"Waiting {attack_result_file_path}...")
        lines = []
        while not os.path.exists(attack_result_file_path) or len(lines) < 50:
            if os.path.exists(attack_result_file_path):
                with open(attack_result_file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            time.sleep(5)
        
        attack_results = [PayloadResult(**json.loads(line)) for line in lines]
        bypassed_payloads = [p for p in attack_results if p.bypassed]
        blocked_payloads = [p for p in attack_results if not p.bypassed]
        num_bypassed = len(bypassed_payloads)
        num_blocked = len(blocked_payloads)
        
        for i in tqdm.tqdm(range(num_payloads), desc=f"{waf_name}({waf_index+1}/{len(WAF_DVWA_URLS)}) | {attack_type}({attack_type_index+1}/{len(VALID_ATTACK_TYPES)})"):
            # Chọn ngẫu nhiên 50% của bypassed và 50% của blocked
            probe_history = []
            sample_bypassed = random.sample(bypassed_payloads, k=max(1, num_bypassed // 2)) if num_bypassed > 0 else []
            sample_blocked = random.sample(blocked_payloads, k=max(1, num_blocked // 2)) if num_blocked > 0 else []
            probe_history.extend(sample_bypassed)
            probe_history.extend(sample_blocked)
            payload_result = generate_payload_phase3(waf_name, attack_type, probe_history)
            attack_result = dvwa.attack(
                attack_type,
                payload_result.payload,
                SESSION_IDS[waf_name],
                WAF_DVWA_URLS[waf_name]
            )
            payload_result.bypassed = attack_result.blocked == False
            payload_result.status_code = attack_result.status_code
            with open(os.path.join(payload_log_dir, f"phase3_{waf_name}_{attack_type}.txt"), "a", encoding="utf-8") as f:
                f.write(json.dumps(payload_result.__dict__) + "\n")
            # break
        # break
    # break