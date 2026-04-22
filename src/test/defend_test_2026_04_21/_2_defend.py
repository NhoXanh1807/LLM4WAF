from utils import VALID_ATTACK_TYPES, WAF_DVWA_URLS, PHASES

import os
import sys
import json
sys.stdout.reconfigure(encoding='utf-8')

input_dir = os.path.join(os.path.dirname(__file__), '1_after_convert')
output_dir = os.path.join(os.path.dirname(__file__), '2_after_defend')
for waf in WAF_DVWA_URLS:
    for attack_type in VALID_ATTACK_TYPES:
        for phase in PHASES:
            file_name = f"result.{waf}.{attack_type}.{phase}.json"
            new_file_name = f"defend.{waf}.{attack_type}.{phase}.json"
            with open(os.path.join(input_dir, file_name), 'r', encoding='utf-8') as f:
                payload_results = json.load(f)
            
            