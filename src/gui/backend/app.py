
import datetime
import sys
import os
from typing import List
from flask import Flask, request, jsonify
from flask_cors import CORS

# --- Logging setup: redirect stdout/stderr ---
session_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_dir = os.path.join(os.path.dirname(__file__), "session_logs")
os.makedirs(log_dir, exist_ok=True)
log_filename = f"log_{session_id}.log"
log_path = os.path.join(log_dir, log_filename)
    

class TeeStream:
    def __init__(self, *streams):
        self.streams = streams
    def write(self, data):
        for s in self.streams:
            try:
                s.write(data)
                s.flush()
            except Exception:
                pass
    def flush(self):
        for s in self.streams:
            try:
                s.flush()
            except Exception:
                pass

# Open log file in append mode
_log_file = open(log_path, 'a', encoding='utf-8')
sys.stdout = TeeStream(sys.__stdout__, _log_file)
sys.stderr = TeeStream(sys.__stderr__, _log_file)

print("importing libs...")
import sys
import os
from typing import List
from flask import Flask, request, jsonify
from flask_cors import CORS

# Add src/ to sys.path so defense/ and validator_syntax_rule/ are importable
_SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# from waf_detector import detect_waf
from wafw00f.main import WAFW00F
from services.generator import PayloadResult, generate_payloads_phase1, generate_payloads_phase3
from services_external import dvwa
from services.generator import PayloadResult
from config.settings import DEFAULT_NUM_DEFENSE_RULES, NGROK_AUTHTOKEN, NGROK_DOMAIN

# Full defense pipeline: clustering -> RAG -> LLM -> syntax validator -> Gemini
from defense.defense_pipeline import DefensePipeline
from validator_syntax_rule.base import WAFType

# Lazy-initialized pipeline instance (shared across requests)
_defense_pipeline: DefensePipeline = None

def _get_pipeline() -> DefensePipeline:
    global _defense_pipeline
    if _defense_pipeline is None:
        _docs_folder = os.path.join(os.path.dirname(__file__), 'RAG', 'docs') + os.sep
        _defense_pipeline = DefensePipeline(
            docs_folder=_docs_folder,
            enable_rag=True,
            enable_gemini=True,
            enable_clustering=True,
        )
    return _defense_pipeline
_get_pipeline()

_WAF_NAME_MAP = {
    "modsecurity": WAFType.MODSECURITY,
    "cloudflare": WAFType.CLOUDFLARE,
    "aws": WAFType.AWS_WAF,
    "naxsi": WAFType.NAXSI,
}

def _map_waf_type(waf_name: str) -> WAFType:
    """Map WAFW00F string to WAFType enum. Defaults to MODSECURITY."""
    name_lower = (waf_name or "").lower()
    for key, waf_type in _WAF_NAME_MAP.items():
        if key in name_lower:
            return waf_type
    return WAFType.MODSECURITY

print("Setting-up Flask app...")
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000", "http://localhost:3001"])

@app.route("/api/detect_waf", methods=["POST"])
def api_detect_waf():
    try:
        data = dict(request.get_json())
        domain = dict.get(data, "domain")
        if not domain:
            return jsonify({"error": "Missing 'domain' field"}), 400
        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "http://" + domain
        w = WAFW00F(domain)
        waf_info = w.identwaf()
        waf_name = waf_info[0][0] if len(waf_info[0]) > 0 else "NO_WAF_INFORMATION"

        return jsonify({"domain": domain, "waf_name": waf_name}), 200
    except Exception as e:
        import traceback
        print("=" * 50)
        print("ERROR in /api/detect_waf:")
        print(traceback.format_exc())
        print("=" * 50)
        return jsonify({"error": str(e)}), 500


@app.route("/api/generate_payload", methods=["POST"])
def api_attack():
    try:
        data = dict(request.get_json())
        waf_name = dict.get(data, "waf_name")
        attack_type = dict.get(data, "attack_type")
        num_payloads = dict.get(data, "num_payloads", 5)
        payloads_history = dict.get(data, "payloads_history", [])
        probe_history = [PayloadResult(**h) for h in payloads_history]
        
        if attack_type not in dvwa.VALID_ATTACK_TYPES:
            return jsonify({"error": "'attack_type' must be in " + str(dvwa.VALID_ATTACK_TYPES)}), 400

        if len(probe_history) <= 0:
            payloads = generate_payloads_phase1(
                waf_name, attack_type, num_of_payloads=num_payloads
            )  # type: List[PayloadResult]
        else:
            payloads = generate_payloads_phase3(
                waf_name, attack_type, num_of_payloads=num_payloads, probe_history=probe_history
            )  # type: List[PayloadResult]
        
        return (
            jsonify(
                {
                    "waf_name": waf_name,
                    "attack_type": attack_type,
                    "payloads": payloads,
                }
            ),
            200,
        )
        
    except Exception as e:
        import traceback
        print("=" * 50)
        print("ERROR in /api/attack:")
        print(traceback.format_exc())
        print("=" * 50)
        return jsonify({"error": str(e)}), 500


@app.route("/api/attack_dvwa", methods=["POST"])
def api_attack_dvwa():
    try:
        data = dict(request.get_json())
        domain = dict.get(data, "domain", None)
        payloads = dict.get(data, "payloads", [])
        payloads = [PayloadResult(**p) for p in payloads]
        
        if not domain:
            return jsonify({"error": "Missing 'domain' field"}), 400

        # Login to DVWA at target domain for retesting
        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "http://" + domain
        print(f"[DVWA-Signin] {domain}...")
        session_id = dvwa.loginDVWA(base_url=domain)
        
        for i, item in enumerate(payloads):
            payload = item.payload
            attack_type = item.attack_type
            attack_func = dvwa.DVWA_ATTACK_FUNC.get(attack_type)

            print(f"[DVWA-Check] {i+1}/{len(payloads)} : {payload.payload}")
            if attack_func and payload:
                result = dvwa.attack(attack_type, payload, session_id, base_url=domain)
                payload.bypassed = not result.blocked
                payload.status_code = result.status_code
                print(f"\t{('BYPASSED' if payload.bypassed else 'BLOCKED')} code({payload.status_code})")
            else:
                payload.bypassed = None
                payload.status_code = None
                print(f"\tSKIPPED (missing attack_func or payload)")
            
        return jsonify({"payloads": payloads}), 200
    except Exception as e:
        import traceback
        print("=" * 50)
        print("ERROR in /api/attack_dvwa:")
        print(traceback.format_exc())
        print("=" * 50)
        return jsonify({"error": str(e)}), 500


def _parse_existing_rules(raw: object) -> list:
    """
    Parse existing_rules from various input formats:
    - list of strings → return as-is
    - list of dicts with "rule" key → extract rule strings
    - newline-separated string (TXT content) → split lines
    - JSON string → parse then extract
    """
    if not raw:
        return []
    if isinstance(raw, list):
        rules = []
        for item in raw:
            if isinstance(item, str):
                rules.append(item.strip())
            elif isinstance(item, dict):
                r = item.get("rule", "")
                if r:
                    rules.append(r.strip())
        return [r for r in rules if r]
    if isinstance(raw, str):
        raw = raw.strip()
        if raw.startswith("[") or raw.startswith("{"):
            try:
                parsed = __import__("json").loads(raw)
                return _parse_existing_rules(parsed)
            except Exception:
                pass
        # Plain text: one rule per line
        return [line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]
    return []


@app.route("/api/defend", methods=["POST"])
def api_defend():
    try:
        data = dict(request.get_json())
        waf_name = dict.get(data, "waf_name")
        payloads = dict.get(data, "payloads", [])
        payloads = [PayloadResult(**payload) for payload in payloads]
        num_rules = dict.get(data, "num_rules", DEFAULT_NUM_DEFENSE_RULES)
        existing_rules_raw = dict.get(data, "existing_rules", None)
        existing_rules = _parse_existing_rules(existing_rules_raw)
        if existing_rules:
            print(f"[Defend] Advanced Defense Mode: {len(existing_rules)} existing rules loaded for comparison")
        bypassed_payloads = [payload for payload in payloads if payload.bypassed]
        pipeline_result = _get_pipeline().generate_defense_rules(
            bypassed_payloads=bypassed_payloads,
            waf_name=waf_name,
            waf_type=_map_waf_type(waf_name),
            num_rules=num_rules,
            existing_rules=existing_rules if existing_rules else None
        )

        return jsonify({
            "rules": [rule.to_dict() for rule in pipeline_result.final_rules],
            "stats": pipeline_result.to_dict()["stats"],
            "clustered_payloads": [cluster.__dict__ for cluster in pipeline_result.cluster_info],
            "advanced_defense": bool(existing_rules),
            "existing_rules_count": len(existing_rules)
        }), 200

    except Exception as e:
        import traceback
        print("=" * 50)
        print("ERROR in /api/defend:")
        print(traceback.format_exc())
        print("=" * 50)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("Starting Flask app...")
    app.run(host="0.0.0.0", port=5000, debug=True)
