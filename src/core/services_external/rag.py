# import requests
# LLMSHIELD_ENDPOINT = "https://overrigged-savingly-nelle.ngrok-free.dev"


# def rag_retrieve(
#     attack_type: str, 
#     waf_name: str, 
#     bypassed_payloads: list = [], 
#     initial_k: int = 10, 
#     final_k:int = 5,
#     filter_rules_only: bool = True
# ) -> dict|None:
#     try:
#         data = {
#             "attack_type": attack_type,
#             "waf_name": waf_name,
#             "bypassed_payloads": bypassed_payloads,
#             "initial_k": initial_k,
#             "final_k": final_k,
#             "filter_rules_only": filter_rules_only
#         }
#         url = LLMSHIELD_ENDPOINT + "?action=" + "rag_retrieve"
#         response = requests.post(url, json=data)
#         """
#         {
#             "rag_enabled": self.enable_rag,
#             "num_queries": 0,
#             "num_docs_all": 0,
#             "num_docs_filtered": 0,
#             "sources": [],
#         }
#         """
#         return response.json()
#     except Exception as e:
#         print(f"Error in rag_retrieve: {str(e)}")
#         return None

"""
LLM4WAF services_external/rag.py

HTTP client for LLMShield RAG.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import requests


LLMSHIELD_ENDPOINT = os.getenv(
    "LLMSHIELD_ENDPOINT",
    "https://overrigged-savingly-nelle.ngrok-free.dev",
).rstrip("/")


UNKNOWN_ATTACK_TYPES = {"", "unknown", "none", "null", "undefined", "n/a", "na"}


def _clean_attack_type(attack_type: Any) -> str:
    if attack_type is None:
        return ""
    return str(attack_type).strip()


def rag_retrieve(
    attack_type: str,
    waf_name: str,
    bypassed_payloads: Optional[list] = None,
    initial_k: int = 16,
    final_k: int = 5,
    filter_rules_only: bool = True,
) -> dict:
    """
    Call LLMShield RAG.

    This function assumes services.rag has already resolved attack_type. It still
    validates the value to prevent accidental retrieval queries with "unknown".
    """
    bypassed_payloads = bypassed_payloads or []
    resolved_attack_type = _clean_attack_type(attack_type)

    if resolved_attack_type.lower() in UNKNOWN_ATTACK_TYPES:
        return {
            "type": "error",
            "message": "Invalid attack_type for RAG. Refusing to call LLMShield with unknown attack_type.",
            "attack_type_input": attack_type,
            "sources": [],
            "queries": [],
            "rag_enabled": False,
        }

    data = {
        "attack_type": resolved_attack_type,
        "waf_name": waf_name,
        "bypassed_payloads": bypassed_payloads,
        "initial_k": int(initial_k),
        "final_k": int(final_k),
        "filter_rules_only": bool(filter_rules_only),
    }

    url = f"{LLMSHIELD_ENDPOINT}?action=rag_retrieve"

    try:
        print(f"[LLM4WAF -> LLMShield RAG] url={url}")
        print(f"[LLM4WAF -> LLMShield RAG] attack_type={resolved_attack_type!r}, waf_name={waf_name!r}")

        response = requests.post(url, json=data, timeout=90)
        response.raise_for_status()

        try:
            result = response.json()
        except ValueError:
            return {
                "type": "error",
                "message": "LLMShield RAG returned non-JSON response.",
                "status_code": response.status_code,
                "raw_response": response.text[:1000],
                "sources": [],
                "queries": [],
            }

        if not isinstance(result, dict):
            return {
                "type": "error",
                "message": f"LLMShield RAG returned {type(result).__name__}, expected dict.",
                "raw_response": result,
                "sources": [],
                "queries": [],
            }

        result.setdefault("attack_type_sent", resolved_attack_type)
        return result

    except Exception as e:
        print(f"Error in rag_retrieve: {str(e)}")
        return {
            "type": "error",
            "message": str(e),
            "attack_type_sent": resolved_attack_type,
            "sources": [],
            "queries": [],
        }
