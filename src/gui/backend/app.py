from typing import List
from flask import Flask, request, jsonify
from flask_cors import CORS

# from waf_detector import detect_waf
from wafw00f.main import WAFW00F
from llm_helper.llm import PayloadResult
import utils
import json
import requests

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])




@app.route("/api/attack", methods=["POST"])
def api_attack():
    try:
        data = dict(request.get_json())
        domain = dict.get(data, "domain")
        attack_type = dict.get(data, "attack_type")
        num_payloads = dict.get(data, "num_payloads", 5)
        payloads_history = dict.get(data, "payloads_history", [])
        probe_history = [PayloadResult(**h) for h in payloads_history]
        
        if not domain:
            return jsonify({"error": "Missing 'domain' field"}), 400

        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "https://" + domain
        
        if attack_type not in utils.VALID_ATTACK_TYPES:
            return jsonify({"error": "'attack_type' must be in " + str(utils.VALID_ATTACK_TYPES)}), 400

        # Get WAF information
        w = WAFW00F(domain)
        waf_info = w.identwaf()
        waf_name = waf_info[0][0] if len(waf_info[0]) > 0 else "NO_WAF_INFORMATION"

        # openai_result = utils.generate_payloads_from_domain_waf_info(
        #     waf_name, attack_type, num_payloads
        # )
        # openai_result = dict(openai_result)
        # content = (
        #     openai_result.get("choices", [])[0].get("message", {}).get("content", None)
        # )
        # content_json = json.loads(content) if content else {}
        # instructions = content_json.get("items", [])

        if len(probe_history) <= 0:
            payloads = utils.generate_payload_phase1(
                waf_name, attack_type, num_of_payloads=num_payloads
            )  # type: List[PayloadResult]
        else:
            payloads = utils.generate_payload_phase3(
                waf_name, attack_type, num_of_payloads=num_payloads, probe_history=probe_history
            )  # type: List[PayloadResult]

        # Login to DVWA
        session_id = utils.loginDVWA()
        
        # Test each payload
        for i in range(len(payloads)):
            payload = payloads[i]
            attack_func = utils.DVWA_ATTACK_FUNC.get(payload.attack_type)
            result = attack_func(payload.payload, session_id)
            payload.bypassed = not result["blocked"]
            payload.status_code = result["status_code"]
            print(f"Tested {i+1}/{len(payloads)} -> {('BYPASSED' if payload.bypassed else 'BLOCKED')} code({payload.status_code}) : {payload.payload}")

        # Auto-generate defense rules if any payload bypassed
        bypassed_payloads = [payload.payload for payload in payloads if payload.bypassed]
        bypassed_instructions = ["Put the payload into any input on vul web then submit" for bypassed_payload in bypassed_payloads]
        defense_rules = []
        if len(bypassed_payloads) > 0:
            print("Generating defense rules for bypassed payloads...")
            defend_result = utils.generate_defend_rules_and_instructions(
                waf_name, bypassed_payloads, bypassed_instructions
            )
            defend_result = dict(defend_result)
            defend_content = defend_result.get("choices", [])[0].get("message", {}).get("content", None)
            defend_json = json.loads(defend_content) if defend_content else {}
            defense_rules = defend_json.get("items", [])

        return (
            jsonify(
                {
                    "domain": domain,
                    "waf_name": waf_name,
                    "payloads": payloads,
                    "defense_rules": defense_rules,
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


@app.route("/api/retest", methods=["POST"])
def api_retest():
    try:
        data = dict(request.get_json())
        bypassed_payloads = dict.get(data, "bypassed_payloads", [])

        if not bypassed_payloads:
            return jsonify({"error": "No payloads provided for retest"}), 400

        # Login to DVWA
        session_id = utils.loginDVWA()


        # Retest each payload
        results = []
        for item in bypassed_payloads:
            payload = item.get("payload")
            attack_type = item.get("attack_type")
            attack_func = utils.DVWA_ATTACK_FUNC.get(attack_type)

            if attack_func and payload:
                result = attack_func(payload, session_id)
                results.append({
                    "payload": payload,
                    "attack_type": attack_type,
                    "bypassed": not result["blocked"],
                    "status_code": result["status_code"]
                })
            else:
                results.append({
                    "payload": payload,
                    "attack_type": attack_type,
                    "bypassed": False,
                    "status_code": None,
                    "error": "Invalid attack type or payload"
                })

        return jsonify({"results": results}), 200
    except Exception as e:
        import traceback
        print("=" * 50)
        print("ERROR in /api/retest:")
        print(traceback.format_exc())
        print("=" * 50)
        return jsonify({"error": str(e)}), 500


@app.route("/api/defend", methods=["POST"])
def api_defend():
    try:
        data = dict(request.get_json())

        waf_info = dict.get(data, "waf_info")
        bypassed_payloads = dict.get(data, "bypassed_payloads")
        bypassed_instructions = dict.get(data, "bypassed_instructions")
        if not waf_info or not bypassed_payloads or not bypassed_instructions:
            return (
                jsonify(
                    {
                        "error": "Missing 'waf_info' or 'bypassed_payloads' or 'bypassed_instructions' field"
                    }
                ),
                400,
            )

        openai_result = utils.generate_defend_rules_and_instructions(
            waf_info, bypassed_payloads, bypassed_instructions
        )
        # return jsonify(openai_result)
        openai_result = dict(openai_result)
        content = (
            openai_result.get("choices", [])[0].get("message", {}).get("content", None)
        )
        content_json = json.loads(content) if content else {}
        rules = content_json.get("items", [])

        return jsonify({"rules": rules, "raw_openai_response": openai_result}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
