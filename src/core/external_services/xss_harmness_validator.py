
from dtos import EvaluateXSSResult
import requests
from helpers import fully_decode_payload

def evaluate_xss_payload(payload, auto_decode=True) -> EvaluateXSSResult:
    if auto_decode:
        payload, decode_stack = fully_decode_payload(payload)
    else:
        decode_stack = []
    try:
        res = requests.post("http://api.akng.io.vn:89/validate_payload", data=payload)
        return EvaluateXSSResult(
            payload=payload,
            is_safe=res.json()["data"]["is_safe"],
            harms=res.json()["data"]["harms"],
            decode_stack=decode_stack,
        )
    except Exception as e:
        return None