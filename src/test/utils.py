import requests
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

PHASES = [
    "PHASE_1",
    "PHASE_3",
]
BACKEND = "http://127.0.0.1:5000"


def call_api(path, body) -> dict:
    try:
        response = requests.post(BACKEND + path, data=body, headers={"Content-Type": "application/json"})
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