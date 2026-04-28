

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
import requests
sys.stdout.reconfigure(encoding='utf-8')
from utils import VALID_ATTACK_TYPES, WAF_DVWA_URLS, PHASES

API_DEFEND_URL = os.environ.get("DEFEND_API_URL", "http://127.0.0.1:5000/api/defend")


def call_defend_api(waf_name: str, payloads: list, attack_type:str, existing_rules: list[str] = None, llm_provider: str = None) -> dict:
    request_data = {
        "waf_name": waf_name,
        "payloads": payloads,
        "attack_type": attack_type,
        "existing_rules": existing_rules,
        "llm_provider": llm_provider,
    }
    request_json = json.dumps(request_data, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(API_DEFEND_URL, data=request_json, headers=headers)
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


def main():
    
    
    # try:
    #     from google import genai
    #     client = genai.Client(api_key="AIzaSyCo_rfIRaKRkwG_vn-yOihKyiQX8MtI6lA")
    #     response = client.models.generate_content(
    #         model="gemini-2.5-flash",
    #         contents="Hello",
    #     )
    #     print(response.text)
    # except ImportError:
    #     print("Google GenAI library not found. Please install it to run the defense pipeline.")
    
    # exit()
    
    os.makedirs(output_dir, exist_ok=True)
    
    with open(os.path.join(os.path.dirname(__file__), "naxsi_core.rules"), "r", encoding="utf-8") as f:
        naxsi_rules = [line.strip() for line in f.readlines() if not line.startswith('#') and line.strip()]
    with open(os.path.join(os.path.dirname(__file__), "REQUEST-941-APPLICATION-ATTACK-XSS.conf"), "r", encoding="utf-8") as f:
        modsec_xss_rules = [line.strip() for line in f.readlines() if not line.startswith('#') and line.strip()]
    with open(os.path.join(os.path.dirname(__file__), "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"), "r", encoding="utf-8") as f:
        modsec_sqli_rules = [line.strip() for line in f.readlines() if not line.startswith('#') and line.strip()]
    waf_attack_type_mapping = {
        "ModSecurity": "xss_stored",
        "Naxsi":"xss_dom",
        "Cloudflare":"sql_injection_blind",
        "AWS":"sql_injection",
    }
    
    for llm_model in ["gpt-5.4", "claude"]:
        for waf in WAF_DVWA_URLS:
            attack_type = waf_attack_type_mapping.get(waf)
            phase = "PHASE_3" if waf != "Cloudflare" else "PHASE_1"
            file_name = f"result.{waf}.{attack_type}.{phase}.json"
            new_file_name = f"defend.{llm_model}.{waf}.{attack_type}.{phase}.json"
            input_path = os.path.join(input_dir, file_name)
            output_path = os.path.join(output_dir, new_file_name)

            print(f"[{waf}|{attack_type}|{phase}] Loading {input_path}")
            with open(input_path, 'r', encoding='utf-8') as f:
                payload_results = json.load(f)

            print(f"[{waf}|{attack_type}|{phase}] Calling {API_DEFEND_URL} for waf={waf}, attack_type={attack_type}, phase={phase}")
            existing_rules = None
            if waf.lower() == "naxsi":
                existing_rules = naxsi_rules
            elif waf.lower() == "modsecurity":
                if "xss" in attack_type.lower():
                    existing_rules = modsec_xss_rules
                elif "sql" in attack_type.lower():
                    existing_rules = modsec_sqli_rules

            result = call_defend_api(
                waf_name=waf, 
                payloads=payload_results, 
                existing_rules=existing_rules, 
                attack_type=attack_type,
                llm_provider=llm_model
            )

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=4)

            print(f"[{waf}|{attack_type}|{phase}] Saved {output_path}")


input_dir = os.path.join(os.path.dirname(__file__), '1_after_convert')
output_dir = os.path.join(os.path.dirname(__file__), '2_after_defend')


if __name__ == "__main__":
    main()
            
