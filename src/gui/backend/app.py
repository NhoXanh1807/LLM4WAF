from flask import Flask, request, jsonify
from flask_cors import CORS
from waf_detector import detect_waf

app = Flask(__name__)
# Enable CORS for frontend with credentials
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

@app.route("/api/detect/waf", methods=["POST"])
def api_detect_waf():
    data = request.get_json()
    if not data or "domain" not in data:
        return jsonify({"error": "Missing 'domain' field"}), 400

    domain = data["domain"].strip()
    result = detect_waf(domain)
    return jsonify(result)

if __name__ == "__main__":
    # Run Flask app on localhost:5000
    app.run(host="0.0.0.0", port=6543, debug=True)
