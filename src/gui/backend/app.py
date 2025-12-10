from flask import Flask, request, jsonify
from flask_cors import CORS
from waf_detector import detect_waf

app = Flask(__name__)
# Enable CORS for frontend with credentials
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

@app.route("/api/detect/waf", methods=["POST"])
def api_detect_waf():
<<<<<<< Updated upstream
    data = request.get_json()
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' field"}), 400
=======
    data = dict(request.get_json())

    domain = dict.get(data, "domain")
    attack_type = dict.get(data, "attack_type")
    num_of_payloads = int(dict.get(data, "num", 5))
    if not domain or not attack_type:
        return jsonify({"error": "Missing 'domain' or 'attack_type' field"}), 400

    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "https://" + domain

    # Get WAF information
    w = WAFW00F(domain)
    waf_info = w.identwaf()[0]
    if len(waf_info) > 0:
        waf_info = waf_info[0]

    openai_result = utils.generate_payloads_from_domain_waf_info(waf_info, attack_type, num_of_payloads)
    openai_result = dict(openai_result)
    # return jsonify(openai_result), 200
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


@app.route("/api/defend", methods=["POST"])
def api_test():
    data = dict(request.get_json())

    waf_info = dict.get(data, "waf_info")
    bypassed_payloads = dict.get(data, "bypassed_payloads")
    bypassed_instructions = dict.get(data, "bypassed_instructions")
    num_of_rules = int(dict.get(data, "num", 5))
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
        waf_info, bypassed_payloads, bypassed_instructions, num_of_rules
    )
    # return jsonify(openai_result)
    openai_result = dict(openai_result)
    content = (
        openai_result.get("choices", [])[0].get("message", {}).get("content", None)
    )
    content_json = json.loads(content) if content else {}
    rules = content_json.get("items", [])

    return jsonify({"rules": rules, "raw_openai_response": openai_result}), 200
>>>>>>> Stashed changes

    domain = data["domain"].strip()
    result = detect_waf(domain)
    return jsonify(result)

if __name__ == "__main__":
    # Run Flask app on localhost:5000
    app.run(host="0.0.0.0", port=6543, debug=True)
