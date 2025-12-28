"""
Payload generation service using LLM
"""

import json
import random

from typing import List
from ..llm_helper.llm import *
from ..config.settings import *
from ..config.prompts import *
from .. import utils
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
    techniques = {
        "xss":[
            "SVG Event Handler", "Unicode Normalization", "IMG Tag with OnError",
            "Body Tag with OnLoad", "Javascript Pseudo-protocol in A Tag",
            "Case Manipulation (<ScRiPt>)", "Attribute Injection (breaking out of quotes)"
        ],
        "sqli": [
            "Double URL Encode", "Comment Obfuscation (/**/)", "Inline Comment Versioning (/*!50000*/)",
            "Hex Encoding", "Whitespace Bypass using Newlines/Tabs", "Boolean-based Blind (AND 1=1)",
            "Time-based Blind (SLEEP/BENCHMARK)", "Union Select with Null Bytes",
            "Case Manipulation (SeLeCt/UnIoN)", "Tautology with Arithmetic (AND 10-2=8)"
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
        generated = gemma_2b_model.generate_response(prompt)
        payload = gemma_2b_model.clean_payload(generated)
        results.append(PayloadResult(
            payload=payload,
            technique=technique,
            attack_type=attack_type,
            bypassed=False
        ))
    return results

def generate_payload_phase3(waf_name, attack_type, num_of_payloads=1, probe_history: List[PayloadResult] = []) -> List[PayloadResult]:
    results = []
    for i in range(num_of_payloads):
        print(f"[With history] Generating {i}/{num_of_payloads} {attack_type} using Adaptive Generation")
        prompt = gemma_2b_model.build_phase3_prompt(waf_name, attack_type, probe_history)
        generated = gemma_2b_model.generate_response(prompt)
        payload = gemma_2b_model.clean_payload(generated)
        results.append(PayloadResult(
            payload=payload,
            technique="Adaptive Generation",
            attack_type=attack_type,
            bypassed=False
        ))
    return results