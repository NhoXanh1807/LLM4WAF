
import os
import sys
import json

import tqdm
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../gui/backend")))
from services_external.rag import rag_retrieve



result = rag_retrieve(
    attack_type="sqli",
    waf_name="CloudFlare",
    filter_rules_only=True
)

print(json.dumps(result, indent=4, ensure_ascii=False))