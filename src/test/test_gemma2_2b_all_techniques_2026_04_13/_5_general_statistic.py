import os
import json

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
PHASES = ["PHASE_1", "PHASE_3"]
log_dir = r'K:\Workspace\bku\LLM4WAF\src\test\test_gemma2_2b_all_techniques_2026_04_13\logs\2026-04-13_22-14-32\harmness_hard'
general_result = {}
for waf_name in WAF_DVWA_URLS:
    general_result[waf_name] = {}
    for attack_type in VALID_ATTACK_TYPES:
        result = {}
        for phase in PHASES:
            result[phase] = {}
            file_path = os.path.join(log_dir, f"harmness_hard_{phase}_{waf_name}_{attack_type}.txt")
            with open(file_path, 'r', encoding='utf-8') as f:
                payload_results = [json.loads(line) for line in f.readlines()]
            result[phase]["total_payload"] = len(payload_results)
            result[phase]["bypassed"] = {
                "total_payload": len([p for p in payload_results if p["bypassed"]]),
            }
            result[phase]["blocked"] = {
                "total_payload": len([p for p in payload_results if not p["bypassed"]]),
            }
            
            if 'xss' in attack_type:
                result[phase]["bypassed"]["harmness"] = {
                    "safe": len([p for p in payload_results if p["bypassed"] and p["harmness"]["is_safe"]]),
                    "harm": len([p for p in payload_results if p["bypassed"] and not p["harmness"]["is_safe"]]),
                }
                result[phase]["blocked"]["harmness"] = {
                    "safe": len([p for p in payload_results if not p["bypassed"] and p["harmness"]["is_safe"]]),
                    "harm": len([p for p in payload_results if not p["bypassed"] and not p["harmness"]["is_safe"]]),
                }
            elif 'sql' in attack_type:
                result[phase]["bypassed"]["harmness"] = {
                    "safe": len([p for p in payload_results if p["bypassed"] and len(p["harmness"]["harm_queries"]) <= 0]),
                    "harm": len([p for p in payload_results if p["bypassed"] and len(p["harmness"]["harm_queries"]) > 0]),
                }
                result[phase]["blocked"]["harmness"] = {
                    "safe": len([p for p in payload_results if not p["bypassed"] and len(p["harmness"]["harm_queries"]) <= 0]),
                    "harm": len([p for p in payload_results if not p["bypassed"] and len(p["harmness"]["harm_queries"]) > 0]),
                }
        
        general_result[waf_name][attack_type] = result

with open(os.path.join(log_dir, "../../","general_result_hard.json"), 'w', encoding='utf-8') as f:
    f.write(json.dumps(general_result, indent=4, ensure_ascii=False))

