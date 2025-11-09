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
        if not domain or not attack_type:
            return jsonify({"error": "Missing 'domain' or 'attack_type' field"}), 400

        if not domain.startswith("http://") and not domain.startswith("https://"):
            domain = "https://" + domain

        # Get WAF information
        w = WAFW00F(domain)
        waf_info = w.identwaf()

        openai_result = utils.generate_payloads_from_domain_waf_info(
            waf_info, attack_type
        )
        openai_result = dict(openai_result)
        content = (
            openai_result.get("choices", [])[0].get("message", {}).get("content", None)
        )
        content_json = json.loads(content) if content else {}
        instructions = content_json.get("items", [])

        for ins in instructions:
            if "bypassed" not in ins:
                ins["bypassed"] = False
            if "attack_type" not in ins:
                ins["attack_type"] = attack_type

        payloads = [
            {
                "attack_type": attack_type,
                "payload": ins.get("payload"),
                "bypassed": False,
            }
            for ins in instructions
        ]
        # payloads = []
        # instructions = []
        # openai_result = {}
        return (
            jsonify(
                {
                    "domain": domain,
                    "waf_info": waf_info,
                    "payloads": payloads,
                    "instructions": instructions,
                    "raw_openai_response": openai_result,
                }
            ),
            200,
        )
    except Exception as e:
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
