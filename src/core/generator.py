"""
All generation-related helper functions for payloads and defense rules
"""

import random
from typing import List
from services_external import llm
from dataclasses import asdict

from .dtos import PayloadResult

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
    )

