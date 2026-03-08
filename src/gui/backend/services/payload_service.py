"""
Payload generation service using LLM
"""

import json
import random

from typing import List
from llm_helper.llm import *
from config.settings import *
from config.prompts import *
from services.llm_service import chatgpt_completion
import utils


def _has_gpu() -> bool:
    """Returns True only if GPU is available AND the Gemma base model is fully downloaded."""
    try:
        import torch
        if not torch.cuda.is_available():
            return False
        # Check if Gemma model shards are fully downloaded (no .incomplete files)
        import os, glob
        hf_cache = os.path.expanduser("~/.cache/huggingface/hub/models--google--gemma-2-2b-it")
        incomplete = glob.glob(os.path.join(hf_cache, "**/*.incomplete"), recursive=True)
        if incomplete:
            print(f"[GPU check] Gemma model cache incomplete ({len(incomplete)} file(s) pending) — falling back to GPT-4o")
            return False
        # Confirm at least one large shard exists
        shard1 = glob.glob(os.path.join(hf_cache, "**/model-00001-of-00002.safetensors"), recursive=True)
        if not shard1:
            print("[GPU check] Gemma model-00001-of-00002.safetensors not found — falling back to GPT-4o")
            return False
        return True
    except Exception:
        return False


def _generate_phase1_openai(waf_info, attack_type, num_of_payloads, technique) -> List[PayloadResult]:
    """Fallback: generate Phase 1 payloads using GPT-4o when no GPU."""
    messages = [
        {"role": "system", "content": RED_TEAM_SYSTEM_PROMPT},
        {"role": "user", "content": get_red_team_user_prompt(waf_info, attack_type, num_of_payloads)}
    ]
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "PayloadList",
            "schema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "payload": {"type": "string"},
                                "technique": {"type": "string"}
                            },
                            "required": ["payload", "technique"]
                        }
                    }
                },
                "required": ["items"]
            }
        }
    }
    result = chatgpt_completion(messages=messages, model=OPENAI_MODEL, response_format=response_format)
    content = result.get("choices", [])[0].get("message", {}).get("content", "{}")
    items = json.loads(content).get("items", [])
    return [
        PayloadResult(
            payload=item.get("payload", ""),
            technique=item.get("technique", technique),
            attack_type=attack_type,
            bypassed=False
        )
        for item in items
    ]


def _generate_phase3_openai(waf_name, attack_type, num_of_payloads, probe_history) -> List[PayloadResult]:
    """Fallback: generate Phase 3 adaptive payloads using GPT-4o when no GPU."""
    blocked = [{"payload": p.payload} for p in probe_history if not p.bypassed]
    passed = [{"payload": p.payload} for p in probe_history if p.bypassed]
    adaptive_prompt = build_adaptive_prompt(waf_name, attack_type, blocked, passed, "Adaptive Generation")
    messages = [
        {"role": "system", "content": RED_TEAM_SYSTEM_PROMPT},
        {"role": "user", "content": adaptive_prompt}
    ]
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "PayloadList",
            "schema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "payload": {"type": "string"},
                                "technique": {"type": "string"}
                            },
                            "required": ["payload", "technique"]
                        }
                    }
                },
                "required": ["items"]
            }
        }
    }
    result = chatgpt_completion(messages=messages, model=OPENAI_MODEL, response_format=response_format)
    content = result.get("choices", [])[0].get("message", {}).get("content", "{}")
    items = json.loads(content).get("items", [])
    return [
        PayloadResult(
            payload=item.get("payload", ""),
            technique=item.get("technique", "Adaptive Generation"),
            attack_type=attack_type,
            bypassed=False
        )
        for item in items
    ]
# try:
#     from .llm_service import chatgpt_completion
#     from ..config.settings import OPENAI_MODEL, DEFAULT_NUM_PAYLOADS
#     from ..config.prompts import RED_TEAM_SYSTEM_PROMPT, get_red_team_user_prompt
# except ImportError:
#     from services.llm_service import chatgpt_completion
#     from config.settings import OPENAI_MODEL, DEFAULT_NUM_PAYLOADS
#     from config.prompts import RED_TEAM_SYSTEM_PROMPT, get_red_team_user_prompt
    

def generate_payloads_from_domain_waf_info(waf_info, attack_type, num_of_payloads=None):
    """
    Generate attack payloads using GPT-4 based on WAF fingerprint

    Args:
        waf_info (dict): WAF detection information
        attack_type (str): Type of attack (xss_dom, sql_injection, etc.)
        num_of_payloads (int): Number of payloads to generate

    Returns:
        dict: OpenAI response with generated payloads
    """
    if num_of_payloads is None:
        num_of_payloads = DEFAULT_NUM_PAYLOADS

    # Build messages for LLM
    messages = [
        {
            "role": "system",
            "content": RED_TEAM_SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": get_red_team_user_prompt(
                json.dumps(waf_info),
                attack_type,
                num_of_payloads
            )
        }
    ]

    # Define JSON schema for structured output
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "PayloadList",
            "schema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "payload": {
                                    "type": "string",
                                    "description": "The attack payload",
                                },
                                "instruction": {
                                    "type": "string",
                                    "description": "Short instruction in between 3 to 5 sentences to use the payload",
                                },
                            },
                            "required": ["payload", "instruction"],
                        }
                    }
                },
                "required": ["items"]
            }
        },
    }

    # Call LLM
    chat_result = utils.chatgpt_completion(
        messages=messages,
        model=OPENAI_MODEL,
        response_format=response_format
    )

    # Include messages in response for debugging
    chat_result["messages"] = messages
    return chat_result

def generate_payload_phase1(waf_info, attack_type, num_of_payloads=1) -> List[PayloadResult]:
    if not _has_gpu():
        print("[Phase 1] No GPU detected — falling back to GPT-4o")
        return _generate_phase1_openai(waf_info, attack_type, num_of_payloads, "GPT-4o Fallback")
    techniques = {
        "xss": [
            "obf_double_url_encode+obf_case_random_full_bypass",
            "Event Handler XSS (heuristic)_adv_obf_full_bypass",
            "obf_url_encode+obf_case_random_full_bypass",
            "obf_whitespace_url+obf_case_random_full_bypass",
            "Direct JS Call XSS (manual refine)_non_script_xss",
            "obf_double_url_encode+obf_whitespace_url_full_bypass",
            "SVG onEvent_adv_obf_full_bypass",
            "IMG onerror+Body onLoad_adv_obf_full_bypass",
        ],
        "sqli": [
            "obf_double_url_encode+obf_whitespace_url+obf_comment_sql_full_bypass",
            "obf_comment_sql+obf_double_url_encode_adv_obf_full_bypass",
            "obf_case_random+obf_comment_sql_version+obf_double_url_encode_full_bypass",
            "obf_double_url_encode+obf_url_encode_adv_obf_full_bypass",
            "obf_whitespace_url+obf_comment_sql_version+obf_double_url_encode_adv_obf_full_bypass",
            "Boolean-based Blind_full_bypass",
            "Time-based Blind_full_bypass",
            "Union Select Null Bytes_adv_obf_full_bypass",
            "obf_case_random+obf_double_url_encode_adv_obf_full_bypass",
        ]
    }
    results = []
    for i in range(num_of_payloads):
        if "xss" in attack_type.lower():
            selected_techniques = random.sample(techniques["xss"], random.randint(1, int(len(techniques["xss"])/2)))
        elif "sql" in attack_type.lower():
            selected_techniques = random.sample(techniques["sqli"], random.randint(1, int(len(techniques["sqli"])/2)))
        technique = "+".join(selected_techniques)
        
        print(f"[No history] Generating {i}/{num_of_payloads} {attack_type} using {technique}")
        prompt = gemma_2b_model.build_phase1_prompt(waf_info, attack_type, technique)
        generated = gemma_2b_model.generate_response(prompt, adapter_name="phase1")
        payload = gemma_2b_model.clean_payload(generated)
        if not gemma_2b_model._is_valid_payload(payload, attack_type):
            print(f"[Phase 1] Model output invalid, using curated fallback payload")
            payload = gemma_2b_model.get_fallback_payload(attack_type)
        results.append(PayloadResult(
            payload=payload,
            technique=technique,
            attack_type=attack_type,
            bypassed=False
        ))
    return results

def generate_payload_phase3(waf_name, attack_type, num_of_payloads=1, probe_history: List[PayloadResult] = []) -> List[PayloadResult]:
    if not _has_gpu():
        print("[Phase 3] No GPU detected — falling back to GPT-4o")
        return _generate_phase3_openai(waf_name, attack_type, num_of_payloads, probe_history)
    results = []
    for i in range(num_of_payloads):
        print(f"[With history] Generating {i}/{num_of_payloads} {attack_type} using Adaptive Generation")
        prompt = gemma_2b_model.build_phase3_prompt(waf_name, attack_type, probe_history)
        generated = gemma_2b_model.generate_response(prompt, adapter_name="phase3_rl")
        payload = gemma_2b_model.clean_payload(generated)
        if not gemma_2b_model._is_valid_payload(payload, attack_type):
            print(f"[Phase 3] Model output invalid, using curated fallback payload")
            payload = gemma_2b_model.get_fallback_payload(attack_type)
        results.append(PayloadResult(
            payload=payload,
            technique="Adaptive Generation",
            attack_type=attack_type,
            bypassed=False
        ))
    return results

