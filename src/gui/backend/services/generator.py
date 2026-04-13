"""
All generation-related helper functions for payloads and defense rules
"""

import json
import random
from typing import List
from services_external import llm
from services import rag
from dataclasses import asdict
from config.settings import OPENAI_MODEL, DEFAULT_NUM_DEFENSE_RULES
from config.prompts import BLUE_TEAM_SYSTEM_PROMPT, RED_TEAM_SYSTEM_PROMPT, get_red_team_user_prompt, get_blue_team_user_prompt, build_adaptive_prompt
from classes import PayloadResult

ATTACK_OBFUSCATE_TECHNIQUES = {
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

def _generate_phase1_openai(waf_name, attack_type, num_of_payloads, technique) -> List[PayloadResult]:
    """Fallback: generate Phase 1 payloads using GPT-4o when no GPU."""
    messages = [
        {"role": "system", "content": RED_TEAM_SYSTEM_PROMPT},
        {"role": "user", "content": get_red_team_user_prompt(waf_name, attack_type, num_of_payloads)}
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
    result = llm.chatgpt_completion(messages=messages, model=OPENAI_MODEL, response_format=response_format)
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
    result = llm.chatgpt_completion(messages=messages, model=OPENAI_MODEL, response_format=response_format)
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


def generate_payloads_phase1(waf_name:str, attack_type, num_of_payloads=1) -> List[PayloadResult]:
    results = []
    for i in range(num_of_payloads):
        print(f"[RANDOM-PAYLOAD] {i}/{num_of_payloads} | {attack_type}")
        payload_result = generate_payload_phase1(waf_name, attack_type)
        print("\tTechniques: " + payload_result.technique)
        print(f"\t{payload_result.payload}")
        results.append(payload_result)
    return results

def generate_payloads_phase3(waf_name, attack_type, num_of_payloads=1, probe_history: List[PayloadResult] = []) -> List[PayloadResult]:
    results = []
    for i in range(num_of_payloads):
        print(f"[ADAPTIVE-PAYLOAD] {i}/{num_of_payloads} | {attack_type} | {len(probe_history)} probe(s)")
        payload_result = generate_payload_phase3(waf_name, attack_type, probe_history)
        print(f"\t{payload_result.payload}")
        results.append(payload_result)
    return results

def generate_payload_phase1(waf_name, attack_type) -> PayloadResult:
    if "xss" in attack_type.lower():
        selected_techniques = random.sample(ATTACK_OBFUSCATE_TECHNIQUES["xss"], random.randint(1, int(len(ATTACK_OBFUSCATE_TECHNIQUES["xss"])/2)))
    elif "sql" in attack_type.lower():
        selected_techniques = random.sample(ATTACK_OBFUSCATE_TECHNIQUES["sqli"], random.randint(1, int(len(ATTACK_OBFUSCATE_TECHNIQUES["sqli"])/2)))
    technique = "+".join(selected_techniques)
    payload = llm.llmshield_generate_payloads(
        waf_name=waf_name,
        attack_type=attack_type,
        techniques=technique,
        adapter_name="phase1"
    )
    return PayloadResult(
        payload=payload,
        technique=technique,
        attack_type=attack_type,
        bypassed=False
    )

def generate_payload_phase3(waf_name, attack_type, probe_history: List[PayloadResult] = []) -> PayloadResult:
    payload = llm.llmshield_generate_payloads(
        waf_name=waf_name,
        attack_type=attack_type,
        probe_history=[asdict(p) for p in probe_history],
        adapter_name="phase3_rl",
    )
    return PayloadResult(
        payload=payload,
        technique="Adaptive Generation",
        attack_type=attack_type,
        bypassed=False
    )


def generate_defend_rules_and_instructions(waf_name, bypassed_payloads, bypassed_instructions, 
    enable_rag=True, docs_folder="./docs/" , filter_rules_only=True):
    """
    Generate ModSecurity defense rules using GPT-4
    ENHANCED: Now supports RAG-based context enrichment

    Args:
        waf_name (str): WAF detection information
        bypassed_payloads (list): List of payloads that bypassed the WAF
        bypassed_instructions (list): Instructions for each bypassed payload
        enable_rag (bool): Whether to use RAG for context enhancement (default: True)
        docs_folder (str): Path to RAG documents folder (default: "./docs/")

    Returns:
        dict: OpenAI response with generated defense rules (includes RAG metadata if used)
    """
    num_of_rules = DEFAULT_NUM_DEFENSE_RULES

    # Generate base user prompt using existing function
    base_user_prompt = get_blue_team_user_prompt(
        waf_name,
        json.dumps(bypassed_payloads),
        json.dumps(bypassed_instructions),
        num_of_rules
    )
    
    # Enhance with RAG if enabled
    if enable_rag:
        rag_result = rag.enhance_defense_generation(
            waf_name=waf_name,
            bypassed_payloads=bypassed_payloads,
            bypassed_instructions=bypassed_instructions,
            base_user_prompt=base_user_prompt,
            docs_folder=docs_folder,
            enable_rag=True,
            filter_rules_only=filter_rules_only
        )
        
        user_prompt = rag_result["enhanced_prompt"]
        rag_metadata = {
            "rag_used": rag_result["rag_used"],
            "sources": rag_result["sources"],
            "num_docs": rag_result.get("num_docs", 0),
            "num_queries": rag_result.get("num_queries", 0)
        }
    else:
        user_prompt = base_user_prompt
        rag_metadata = {
            "rag_used": False,
            "sources": [],
            "num_docs": 0,
            "num_queries": 0
        }

    # Build messages for LLM
    messages = [
        {
            "role": "system",
            "content": BLUE_TEAM_SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": user_prompt
        }
    ]

    # Define JSON schema for structured output
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "DefenseRuleList",
            "schema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "rule": {
                                    "type": "string",
                                    "description": "The WAF rule or configuration to implement",
                                },
                                "instructions": {
                                    "type": "string",
                                    "description": "Short instructions on how to implement the rule",
                                },
                            },
                            "required": ["rule", "instructions"],
                        }
                    }
                },
                "required": ["items"]
            }
        },
    }

    # Call LLM
    chat_result = llm.chatgpt_completion(
        messages=messages,
        model=OPENAI_MODEL,
        response_format=response_format
    )

    # Include messages and RAG metadata in response for debugging
    chat_result["messages"] = messages
    chat_result["rag_metadata"] = rag_metadata
    
    return chat_result