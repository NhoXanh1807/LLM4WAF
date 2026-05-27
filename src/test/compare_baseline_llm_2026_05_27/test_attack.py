
import os
import sys
import json
sys.stdout.reconfigure(encoding='utf-8')
sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    "../../core"
)))

from attack_pipeline import _3_test_attack
from models.dtos import PayloadResult

payloads = {
    "xss_reflected": {},
    "sqli": {}
}
with open(os.path.abspath(os.path.join(os.path.dirname(__file__), "baseline_payloads_xss.json")), "r", encoding="utf-8") as f:
    payloads["xss_reflected"] = json.load(f)
with open(os.path.abspath(os.path.join(os.path.dirname(__file__), "baseline_payloads_sqli.json")), "r", encoding="utf-8") as f:
    payloads["sqli"] = json.load(f)

for attack_type, payload_list in payloads.items():
    results = _3_test_attack(
        "modsec.llmshield.click",
        [PayloadResult(**p) for p in payload_list]
    )
    with open(os.path.abspath(os.path.join(os.path.dirname(__file__), f"baseline_test_results_{attack_type}.json")), "w", encoding="utf-8") as f:
        json.dump([result.__dict__ for result in results], f, indent=2)