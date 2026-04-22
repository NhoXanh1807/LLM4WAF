from utils import VALID_ATTACK_TYPES, WAF_DVWA_URLS, PHASES

import os
import sys
import json
sys.stdout.reconfigure(encoding='utf-8')

input_dir = os.path.join(os.path.dirname(__file__), '0_payload_results')
output_dir = os.path.join(os.path.dirname(__file__), '1_after_convert')
for waf in WAF_DVWA_URLS:
    for attack_type in VALID_ATTACK_TYPES:
        for phase in PHASES:
            file_name = f"harmness_{phase}_{waf}_{attack_type}.txt"
            new_file_name = f"result.{waf}.{attack_type}.{phase}.json"
            with open(os.path.join(input_dir, file_name), 'r', encoding='utf-8') as f:
                lines = f.readlines()
            file_output = []
            for line in lines:
                payload_result = json.loads(line)
                if 'xss' in payload_result['attack_type'].lower():
                    is_harmful = not payload_result["harmness"]["is_safe"]
                elif 'sql' in payload_result['attack_type'].lower():
                    is_harmful = len(payload_result["harmness"]["harm_queries"]) > 0
                file_output.append({
                    "payload": payload_result["payload"],
                    "technique": payload_result["technique"],
                    "attack_type": payload_result["attack_type"],
                    "waf": waf,
                    "phase": phase,
                    "status_code": payload_result["status_code"],
                    "is_bypassed": payload_result["bypassed"],
                    "is_harmful": is_harmful,
                    'harmness': payload_result["harmness"]
                })
            with open(os.path.join(output_dir, new_file_name), 'w', encoding='utf-8') as f:
                json.dump(file_output, f, ensure_ascii=False, indent=4)