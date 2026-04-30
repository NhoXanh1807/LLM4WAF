# from typing import List, Dict, Any, Optional
# from services_external.rag import rag_retrieve

# def enhance_defense_generation(
#         attack_type: str,
#         waf_name: str,
#         bypassed_payloads: list,
#         base_user_prompt: str,
#         filter_rules_only: bool = True,
#     ) -> Dict[str, Any]:
    
#     # Call RAG service
#     rag_result = rag_retrieve(
#         attack_type=attack_type,
#         waf_name=waf_name,
#         bypassed_payloads=bypassed_payloads,
#         initial_k=10,
#         final_k=4,
#         filter_rules_only=filter_rules_only
#     )
#     sources = rag_result.get("sources", [])
#     if len(sources) <= 0:
#         enhanced_prompt = base_user_prompt
#     else:
#         context = "\n\n".join([f"[Reference #{i + 1} : {source['source']}]{source['content']}" for i, source in enumerate(sources)])
#         enhanced_prompt = f"""{base_user_prompt}

# ---
# **KNOWLEDGE BASE REFERENCES**

# The following references from our security knowledge base may help inform your defense strategy:

# {context}

# ---

# Please consider these references when generating defense rules, but prioritize the specific bypassed payloads mentioned above.
# """

#     result = {"enhanced_prompt": enhanced_prompt}
#     result.update(rag_result)
#     return result

"""
LLM4WAF services/rag.py

Enhances defense-rule generation prompts with RAG context from LLMShield.
This version resolves and normalizes attack_type before calling LLMShield RAG,
so placeholder values like "unknown" are not forwarded into retrieval queries.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from services_external.rag import rag_retrieve


UNKNOWN_ATTACK_TYPES = {"", "unknown", "none", "null", "undefined", "n/a", "na"}


def _is_unknown_attack_type(value: Any) -> bool:
    if value is None:
        return True
    return str(value).strip().lower() in UNKNOWN_ATTACK_TYPES


def normalize_attack_type_for_rag(value: Any) -> Optional[str]:
    """
    Normalize LLM4WAF attack labels to labels that LLMShield RAG should use in queries.

    Examples:
        xss_reflected, xss_stored, cross-site-scripting -> XSS
        sqli, sql_injection, SQL injection              -> SQLI
    """
    if _is_unknown_attack_type(value):
        return None

    s = str(value).strip().lower()
    normalized = re.sub(r"[\s\-]+", "_", s)

    if "xss" in normalized or "cross_site" in normalized or "crosssite" in normalized:
        return "XSS"
    if "sqli" in normalized or "sql_injection" in normalized or "sqlinjection" in normalized:
        return "SQLI"
    if normalized == "sql" or normalized.startswith("sql_") or " sql " in f" {s} ":
        return "SQLI"
    if "ssrf" in normalized:
        return "SSRF"
    if "rce" in normalized or "cmdi" in normalized or "command_injection" in normalized:
        return "RCE"
    if "lfi" in normalized or "local_file" in normalized or "path_traversal" in normalized:
        return "LFI"
    if "rfi" in normalized or "remote_file" in normalized:
        return "RFI"

    return str(value).strip()


def _extract_attack_type_from_payload_metadata(payloads: list[Any]) -> Optional[str]:
    """
    Read explicit attack_type metadata from payload objects or SimulatedPayload strings.

    This is not heuristic detection. It extracts a real field already produced by the
    payload-generation stage, for example:
        SimulatedPayload({"attack_type": "xss_reflected", ...})
    """
    def visit(obj: Any) -> Optional[str]:
        if obj is None:
            return None

        if isinstance(obj, dict):
            for key in (
                "attack_type", "attackType", "detected_attack_type",
                "selected_attack_type", "attack", "type",
            ):
                if key in obj:
                    candidate = normalize_attack_type_for_rag(obj.get(key))
                    if candidate:
                        return candidate

            for key in ("payload", "prompt", "probe_history", "items", "data"):
                if key in obj:
                    candidate = visit(obj.get(key))
                    if candidate:
                        return candidate

            for value in obj.values():
                candidate = visit(value)
                if candidate:
                    return candidate
            return None

        if isinstance(obj, list):
            for item in obj:
                candidate = visit(item)
                if candidate:
                    return candidate
            return None

        if isinstance(obj, str):
            text = obj.strip()
            if not text:
                return None

            try:
                parsed = json.loads(text)
                candidate = visit(parsed)
                if candidate:
                    return candidate
            except Exception:
                pass

            wrapped = re.search(r"(?:SimulatedPayload|SimulatedPrompt)\((\{.*\})\)", text, flags=re.DOTALL)
            if wrapped:
                try:
                    parsed = json.loads(wrapped.group(1))
                    candidate = visit(parsed)
                    if candidate:
                        return candidate
                except Exception:
                    pass

            for pattern in (
                r'\\?"attack_type\\?"\s*:\s*\\?"([^"\\]+)\\?"',
                r"\\?'attack_type\\?'\s*:\s*\\?'([^'\\]+)\\?'",
                r'\\?"attackType\\?"\s*:\s*\\?"([^"\\]+)\\?"',
            ):
                match = re.search(pattern, text)
                if match:
                    candidate = normalize_attack_type_for_rag(match.group(1))
                    if candidate:
                        return candidate

        return None

    return visit(payloads)


def _detect_attack_type(payloads: list[Any]) -> str:
    """
    Fallback lexical detector.

    It is used only when the caller did not provide attack_type and no explicit metadata
    is found inside the payloads. Metadata always wins over token heuristics.
    """
    metadata_type = _extract_attack_type_from_payload_metadata(payloads)
    if metadata_type:
        return metadata_type

    payload_str = " ".join(str(p) for p in payloads).lower()

    xss_keywords = [
        "xss", "cross site", "cross-site", "script", "<script", "onerror",
        "onload", "onclick", "onmouseover", "alert", "document.cookie",
        "javascript:", "<img", "img", "<svg", "svg", "iframe", "event handler",
    ]
    sql_keywords = [
        "sqli", "sql injection", "union select", "union", "select", "sleep(",
        "benchmark(", "information_schema", "or 1=1", "and 1=1", "' or", '" or',
    ]
    ssrf_keywords = ["ssrf", "169.254.169.254", "metadata", "gopher://", "file://"]
    lfi_keywords = ["../", "..\\", "etc/passwd", "boot.ini", "path traversal", "lfi"]
    rce_keywords = ["rce", "cmdi", "command injection", ";cat", "|cat", "whoami", "bash -c"]

    scores = {
        "XSS": sum(1 for k in xss_keywords if k in payload_str),
        "SQLI": sum(1 for k in sql_keywords if k in payload_str),
        "SSRF": sum(1 for k in ssrf_keywords if k in payload_str),
        "LFI": sum(1 for k in lfi_keywords if k in payload_str),
        "RCE": sum(1 for k in rce_keywords if k in payload_str),
    }
    best_type, best_score = max(scores.items(), key=lambda kv: kv[1])
    return best_type if best_score > 0 else "Unknown"


def resolve_attack_type_for_rag(attack_type: Any, bypassed_payloads: list[Any]) -> str:
    """
    Resolve final attack_type sent to LLMShield RAG.

    Priority:
    1. attack_type argument from pipeline if valid
    2. explicit attack_type metadata in bypassed_payloads
    3. lexical fallback
    4. Unknown
    """
    candidate = normalize_attack_type_for_rag(attack_type)
    if candidate:
        return candidate

    candidate = _extract_attack_type_from_payload_metadata(bypassed_payloads)
    if candidate:
        return candidate

    return _detect_attack_type(bypassed_payloads)


def enhance_defense_generation(
    attack_type: str,
    waf_name: str,
    bypassed_payloads: list,
    base_user_prompt: str,
    filter_rules_only: bool = True,
) -> Dict[str, Any]:
    """Call LLMShield RAG and inject retrieved references into the defense prompt."""

    resolved_attack_type = resolve_attack_type_for_rag(attack_type, bypassed_payloads)

    if _is_unknown_attack_type(resolved_attack_type):
        return {
            "enhanced_prompt": base_user_prompt,
            "rag_used": False,
            "rag_error": (
                "attack_type could not be resolved before RAG call. "
                "Pass attack_type from the generate/test stage or include attack_type metadata in payloads."
            ),
            "attack_type_input": attack_type,
            "resolved_attack_type": resolved_attack_type,
            "sources": [],
            "queries": [],
        }

    print(f"[LLM4WAF RAG] attack_type_input={attack_type!r}")
    print(f"[LLM4WAF RAG] resolved_attack_type_sent={resolved_attack_type!r}")

    rag_result = rag_retrieve(
        attack_type=resolved_attack_type,
        waf_name=waf_name,
        bypassed_payloads=bypassed_payloads,
        initial_k=16,
        final_k=5,
        filter_rules_only=filter_rules_only,
    ) or {}

    if not isinstance(rag_result, dict):
        rag_result = {
            "type": "error",
            "message": f"rag_retrieve returned non-dict response: {type(rag_result).__name__}",
        }

    sources = rag_result.get("sources", []) or []
    rag_context = rag_result.get("context", "") or ""

    if rag_context:
        context = rag_context
    else:
        context = "\n\n".join(
            [
                f"[Reference #{i + 1}: {source.get('source', 'Unknown')}]\n{source.get('content', '')}"
                for i, source in enumerate(sources)
            ]
        )

    if not context.strip():
        enhanced_prompt = base_user_prompt
        rag_used = False
    else:
        enhanced_prompt = f"""{base_user_prompt}

---
**KNOWLEDGE BASE REFERENCES FOR RULE GENERATION**

{context}

---
Use the references above as implementation evidence for writing WAF rules.
Prioritize WAF-specific syntax, fields, operators, transformations, actions, and concrete examples.
Ignore references that only describe the attack generally but do not help write a rule.
Prioritize the specific bypassed payloads mentioned above.
"""
        rag_used = True

    result: Dict[str, Any] = {
        "enhanced_prompt": enhanced_prompt,
        "rag_used": rag_used,
        "attack_type_input": attack_type,
        "resolved_attack_type": resolved_attack_type,
    }
    result.update(rag_result)
    return result
