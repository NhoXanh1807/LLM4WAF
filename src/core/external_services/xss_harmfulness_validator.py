
from models.dtos import EvaluateXSSResult
import requests
from utils.utils import fully_decode_payload
from config.settings import XSS_HARMNESS_VALIDATOR_ENDPOINT

def evaluate_xss_payload(payload, auto_decode=True) -> EvaluateXSSResult:
    if auto_decode:
        payload, decode_stack = fully_decode_payload(payload)
    else:
        decode_stack = []
    try:
        res = requests.post(XSS_HARMNESS_VALIDATOR_ENDPOINT, data=payload)
        return EvaluateXSSResult(
            payload=payload,
            is_safe=res.json()["data"]["is_safe"],
            harms=res.json()["data"]["harms"],
            decode_stack=decode_stack,
        )
    except Exception as e:
        return None