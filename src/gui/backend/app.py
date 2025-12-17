from flask import Flask, request, jsonify
from flask_cors import CORS

# from waf_detector import detect_waf
from wafw00f.main import WAFW00F
import utils
import json

app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])


@app.route("/api/attack", methods=["POST"])
def api_detect_waf():
    try:
        data = dict(request.get_json())

        domain = dict.get(data, "domain")
        attack_type = dict.get(data, "attack_type")
        num_of_payloads = dict.get(data, "num_payloads", 5)
        if not domain or not attack_type:
            return jsonify({"error": "Missing 'domain' or 'attack_type' field"}), 400

        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "https://" + domain

        # Get WAF information
        w = WAFW00F(domain)
        waf_info = w.identwaf()

        USE_LOCAL_LLM = True
        if not USE_LOCAL_LLM:
            openai_result = utils.generate_payloads_from_domain_waf_info(
                waf_info, attack_type, num_payloads
            )
            openai_result = dict(openai_result)
            content = (
                openai_result.get("choices", [])[0].get("message", {}).get("content", None)
            )
            content_json = json.loads(content) if content else {}
            instructions = content_json.get("items", [])
        else:
            payloads = utils.generate_payloads_by_local_llm(
                waf_info, attack_type, num_of_payloads=num_payloads
            )
            instructions = [
                {
                    "payload": p,
                    "instruction": f"Use the payload to perform {attack_type} attack."
                }
                for p in payloads
            ]
            openai_result = None

        # Login to DVWA
        session_id = utils.loginDVWA()

        # Map attack types to functions
        attack_functions = {
            "xss_dom": utils.attack_xss_dom,
            "xss_reflected": utils.attack_xss_reflected,
            "xss_stored": utils.attack_xss_stored,
            "sql_injection": utils.attack_sql_injection,
            "sql_injection_blind": utils.attack_sql_injection_blind,
        }

        # Test each payload
        for ins in instructions:
            payload = ins.get("payload")
            attack_func = attack_functions.get(attack_type)

            if attack_func and payload:
                result = attack_func(payload, session_id)
                ins["bypassed"] = not result["blocked"]  # bypassed = not blocked
                ins["status_code"] = result["status_code"]
            else:
                ins["bypassed"] = False
                ins["status_code"] = None

            ins["attack_type"] = attack_type

        payloads = [
            {
                "attack_type": attack_type,
                "payload": ins.get("payload"),
                "bypassed": ins.get("bypassed", False),
                "status_code": ins.get("status_code"),
            }
            for ins in instructions
        ]

        # Auto-generate defense rules if any payload bypassed
        bypassed_payloads = [ins["payload"] for ins in instructions if ins.get("bypassed")]
        bypassed_instructions = [ins["instruction"] for ins in instructions if ins.get("bypassed")]

        defense_rules = []
        if bypassed_payloads:
            defend_result = utils.generate_defend_rules_and_instructions(
                waf_info, bypassed_payloads, bypassed_instructions
            )
            defend_result = dict(defend_result)
            defend_content = defend_result.get("choices", [])[0].get("message", {}).get("content", None)
            defend_json = json.loads(defend_content) if defend_content else {}
            defense_rules = defend_json.get("items", [])

        return (
            jsonify(
                {
                    "domain": domain,
                    "waf_info": waf_info,
                    "payloads": payloads,
                    "instructions": instructions,
                    "defense_rules": defense_rules,
                    "raw_openai_response": openai_result,
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

        # Map attack types to functions
        attack_functions = {
            "xss_dom": utils.attack_xss_dom,
            "xss_reflected": utils.attack_xss_reflected,
            "xss_stored": utils.attack_xss_stored,
            "sql_injection": utils.attack_sql_injection,
            "sql_injection_blind": utils.attack_sql_injection_blind,
        }

        # Retest each payload
        results = []
        for item in bypassed_payloads:
            payload = item.get("payload")
            attack_type = item.get("attack_type")
            attack_func = attack_functions.get(attack_type)

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
def api_test():
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
