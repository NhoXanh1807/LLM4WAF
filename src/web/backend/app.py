import os
import sys

# Import core
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../core")))

import datetime
import traceback
from functools import wraps

from flask import Flask, jsonify, request
from flask_cors import CORS
from teestream import TeeStream

# --- Logging setup: redirect stdout/stderr ---
session_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
log_dir = os.path.join(os.path.dirname(__file__), "session_logs")
os.makedirs(log_dir, exist_ok=True)
log_path = os.path.join(log_dir, f"log_{session_id}.log")
_log_file = open(log_path, 'a', encoding='utf-8')
sys.stdout = TeeStream(sys.__stdout__, _log_file)
sys.stderr = TeeStream(sys.__stderr__, _log_file)

print("importing libs...")

# Add src/ to sys.path so project modules are importable
_SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from models.dtos import PayloadResult
import attack_pipeline
import defend_pipelines

print("Setting-up Flask app...")
app = Flask(__name__)
CORS(app, supports_credentials=True, origins=["http://localhost:3000", "http://localhost:3001"])


def api_error_handler(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        except Exception as e:
            print("=" * 50)
            print(f"ERROR in {request.path}:")
            print(traceback.format_exc())
            print("=" * 50)
            return jsonify({"error": str(e)}), 500

    return wrapper


def _parse_payload_results(items):
    return [
        PayloadResult(
            payload=item.get("payload", ""),
            technique=item.get("technique", ""),
            attack_type=item.get("attack_type", ""),
            status_code=item.get("status_code"),
            is_bypassed=item.get("is_bypassed"),
            is_harmful=item.get("is_harmful"),
        )
        for item in (items or [])
        if isinstance(item, dict)
    ]


def _extract_bypassed_payloads(payloads):
    return [
        str(item.payload).strip()
        for item in payloads
        if item.is_bypassed and str(item.payload).strip()
    ]

@app.route("/api/attack/1-detect-waf", methods=["POST"])
@api_error_handler
def api_attack_1_detect_waf():
    payload = request.get_json(silent=True)
    data = payload if isinstance(payload, dict) else {}
    domain = dict.get(data, "domain")
    if not domain:
        return jsonify({"error": "Missing 'domain' field"}), 400
    result = attack_pipeline._1_detect_waf(domain=domain)

    return jsonify(result), 200


@app.route("/api/attack/2-generate-payload", methods=["POST"])
@api_error_handler
def api_attack_2_generate_payload():
    payload = request.get_json(silent=True)
    data = payload if isinstance(payload, dict) else {}
    waf_name = dict.get(data, "waf_name")
    attack_type = dict.get(data, "attack_type")
    num_payloads = dict.get(data, "num_payloads", 5)
    payloads_history = dict.get(data, "payloads_history", [])
    probe_history = [
        PayloadResult(
            payload=item.get("payload", ""),
            technique=item.get("technique", ""),
            attack_type=item.get("attack_type", ""),
            status_code=item.get("status_code"),
            is_bypassed=item.get("is_bypassed"),
            is_harmful=item.get("is_harmful"),
        )
        for item in (payloads_history or [])
        if isinstance(item, dict)
    ]
    if not waf_name:
        return jsonify({"error": "Missing 'waf_name' field"}), 400

    payloads = attack_pipeline._2_generate_payload(
        waf_name=waf_name,
        attack_type=attack_type,
        num_payloads=num_payloads,
        payloads_history=probe_history,
    )

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


@app.route("/api/attack/3-test", methods=["POST"])
@api_error_handler
def api_attack_3_test():
    payload = request.get_json(silent=True)
    data = payload if isinstance(payload, dict) else {}
    domain = dict.get(data, "domain", None)
    check_harmful = dict.get(data, "check_harmful", True)
    check_waf = dict.get(data, "check_waf", True)
    payloads = [
        PayloadResult(
            payload=item.get("payload", ""),
            technique=item.get("technique", ""),
            attack_type=item.get("attack_type", ""),
            status_code=item.get("status_code"),
            is_bypassed=item.get("is_bypassed"),
            is_harmful=item.get("is_harmful"),
        )
        for item in dict.get(data, "payloads", [])
        if isinstance(item, dict)
    ]

    if not domain:
        return jsonify({"error": "Missing 'domain' field"}), 400

    tested_payloads = attack_pipeline._3_test_attack(
        domain=domain,
        payloads=payloads,
        check_harmful=check_harmful,
        check_waf=check_waf,
    )

    return jsonify({"payloads": tested_payloads}), 200


@app.route("/api/defend/1-clustering", methods=["POST"])
@api_error_handler
def api_defend_1_clustering():
    payload = request.get_json(silent=True)
    data = payload if isinstance(payload, dict) else {}
    payloads = _parse_payload_results(data.get("payloads", []))
    bypassed_payloads = _extract_bypassed_payloads(payloads)

    clusters = defend_pipelines._1_clustering(
        bypassed_payloads=bypassed_payloads,
    )

    return jsonify({
        "bypassed_payloads": bypassed_payloads,
        "clusters": clusters,
        "stats": {
            "num_bypassed_payloads": len(bypassed_payloads),
            "num_clusters": len(clusters),
        },
    }), 200


@app.route("/api/defend/2-rag-retrieve", methods=["POST"])
@api_error_handler
def api_defend_2_rag_retrieve():
    payload = request.get_json(silent=True)
    data = payload if isinstance(payload, dict) else {}
    waf_name = str(data.get("waf_name", "")).strip()
    attack_type = str(data.get("attack_type", "")).strip()
    if not waf_name:
        return jsonify({"error": "Missing 'waf_name' field"}), 400
    if not attack_type:
        return jsonify({"error": "Missing 'attack_type' field"}), 400
    payloads = _parse_payload_results(data.get("payloads", []))
    bypassed_payloads = _extract_bypassed_payloads(payloads)

    rag_result, rag_sources, rag_context = defend_pipelines._2_rag_retrieve(
        waf_name=waf_name,
        attack_type=attack_type,
        bypassed_payloads=bypassed_payloads,
    )

    return jsonify({
        "waf_name": waf_name,
        "attack_type": attack_type,
        "bypassed_payloads": bypassed_payloads,
        "rag_result": rag_result,
        "rag_sources": rag_sources,
        "rag_context": rag_context,
    }), 200


@app.route("/api/defend/3-generate-rules", methods=["POST"])
@api_error_handler
def api_defend_3_generate_rules():
    payload = request.get_json(silent=True)
    data = payload if isinstance(payload, dict) else {}
    waf_name = str(data.get("waf_name", "")).strip()
    clusters = data.get("clusters", [])
    rag_context = str(data.get("rag_context", ""))
    if not waf_name:
        return jsonify({"error": "Missing 'waf_name' field"}), 400
    if not isinstance(clusters, list):
        return jsonify({"error": "'clusters' must be a list"}), 400

    generated_rules, generation_prompt = defend_pipelines._3_generate_rules(
        waf_name=waf_name,
        clusters=clusters,
        rag_context=rag_context,
    )

    return jsonify({
        "waf_name": waf_name,
        "clusters": clusters,
        "rag_context": rag_context,
        "generation_prompt": generation_prompt,
        "generated_rules": generated_rules,
        "stats": {
            "rules_generated": len(generated_rules),
        },
    }), 200


@app.route("/api/defend/4-validate-rules", methods=["POST"])
@api_error_handler
def api_defend_4_validate_rules():
    payload = request.get_json(silent=True)
    data = payload if isinstance(payload, dict) else {}
    generated_rules = data.get("generated_rules", [])
    if not isinstance(generated_rules, list):
        return jsonify({"error": "'generated_rules' must be a list"}), 400

    valid_rules, invalid_rules = defend_pipelines._4_validate_rules_syntax(
        generated_rules=generated_rules,
    )

    return jsonify({
        "generated_rules": generated_rules,
        "valid_rules": valid_rules,
        "invalid_rules": invalid_rules,
        "stats": {
            "rules_generated": len(generated_rules),
            "rules_valid": len(valid_rules),
            "rules_invalid": len(invalid_rules),
        },
    }), 200


@app.route("/api/defend/5-retry-invalid-rules", methods=["POST"])
@api_error_handler
def api_defend_5_retry_invalid_rules():
    payload = request.get_json(silent=True)
    data = payload if isinstance(payload, dict) else {}
    waf_name = str(data.get("waf_name", "")).strip()
    invalid_rules = data.get("invalid_rules", [])
    if not waf_name:
        return jsonify({"error": "Missing 'waf_name' field"}), 400
    if not isinstance(invalid_rules, list):
        return jsonify({"error": "'invalid_rules' must be a list"}), 400

    retried_rules = defend_pipelines._5_retry_invalid_rules(
        waf_name=waf_name,
        invalid_rules=invalid_rules,
    )

    return jsonify({
        "waf_name": waf_name,
        "invalid_rules": invalid_rules,
        "retried_rules": retried_rules,
        "stats": {
            "rules_invalid": len(invalid_rules),
            "rules_retried": len(retried_rules),
        },
    }), 200


@app.route("/api/defend/6-refine-rules", methods=["POST"])
@api_error_handler
def api_defend_6_refine_rules():
    payload = request.get_json(silent=True)
    data = payload if isinstance(payload, dict) else {}
    waf_name = str(data.get("waf_name", "")).strip()
    valid_rules = data.get("valid_rules", [])
    existing_rules_raw = data.get("existing_rules", [])
    if not waf_name:
        return jsonify({"error": "Missing 'waf_name' field"}), 400
    if not isinstance(valid_rules, list):
        return jsonify({"error": "'valid_rules' must be a list"}), 400

    existing_rules = defend_pipelines._parse_existing_rules(existing_rules_raw)
    final_rules = defend_pipelines._6_refine_rules(
        waf_name=waf_name,
        valid_rules=valid_rules,
        existing_rules=existing_rules,
    )

    return jsonify({
        "waf_name": waf_name,
        "advanced_defense": bool(existing_rules),
        "existing_rules_count": len(existing_rules),
        "existing_rules": existing_rules,
        "valid_rules": valid_rules,
        "final_rules": final_rules,
        "stats": {
            "rules_valid": len(valid_rules),
            "rules_refined": len(final_rules),
            "existing_rules_count": len(existing_rules),
        },
    }), 200


if __name__ == "__main__":
    print("Starting Flask app...")
    app.run(host="0.0.0.0", port=5000, debug=True)
