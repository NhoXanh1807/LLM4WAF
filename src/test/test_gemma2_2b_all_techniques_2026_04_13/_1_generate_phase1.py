

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../core")))


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
from attack_pipeline import _2_generate_payload, _3_test_attack
from models.dtos import PayloadResult

num_payloads = 50
cp_waf_index = 0
cp_attack_type_index = 0
for waf_name, url in WAF_DVWA_URLS.items():
    if waf_name == "ModSecurity" or waf_name == "Naxsi":
        continue
    waf_index = list(WAF_DVWA_URLS.keys()).index(waf_name)
    for attack_type in VALID_ATTACK_TYPES:
        attack_type_index = VALID_ATTACK_TYPES.index(attack_type)
        if waf_index < cp_waf_index or (waf_index == cp_waf_index and attack_type_index < cp_attack_type_index):
            print(f"Skipping {waf_name} - {attack_type}...")
            continue
        
        payload_file = os.path.join(os.path.dirname(__file__), "attack_gemma2_pretrained", f"attack.results.gemma2b_pretrained.ModSecurity.{attack_type}.json")
        with open(payload_file, "r", encoding="utf-8") as f:
            payloads = [PayloadResult(**r) for r in json.load(f)]
        
        results = _3_test_attack(url, payloads)
        
        with open(os.path.join(os.path.dirname(__file__), "attack_gemma2_pretrained", f"attack.results.gemma2b_pretrained.{waf_name}.{attack_type}.json"), "w", encoding="utf-8") as f:
            json.dump([r.__dict__ for r in results], f, ensure_ascii=False, indent=4)
            
        # break
    # break