from typing import Any, Optional

from wafw00f.main import WAFW00F

from dtos import PayloadResult
from services.generator import generate_payloads_phase1, generate_payloads_phase3
from services.payload_harmness_validator import (
    evaluate_sql_payload,
    evaluate_xss_payload,
)
from external_services import dvwa


def _normalize_domain(domain: str) -> str:
    normalized_domain = str(domain or "").strip()
    if not normalized_domain:
        return None
    if not normalized_domain.startswith("http://") and not normalized_domain.startswith("https://"):
        normalized_domain = "http://" + normalized_domain
    return normalized_domain


def _1_detect_waf(domain: str) -> dict[str, str]:
    waf = WAFW00F(domain)
    waf_info = waf.identwaf()
    waf_name = waf_info[0][0] if len(waf_info[0]) > 0 else "NO_WAF_INFORMATION"
    return {
        "domain": domain,
        "waf_name": waf_name,
    }


def _2_generate_payload(
    waf_name: str,
    attack_type: str,
    num_payloads: int = 5,
    payloads_history: Optional[list[PayloadResult]] = None,
) -> list[PayloadResult]:
    probe_history = list(payloads_history or [])
    if not waf_name:
        raise ValueError("Missing 'waf_name' field")
    if attack_type not in dvwa.VALID_ATTACK_TYPES:
        raise ValueError("'attack_type' must be in " + str(dvwa.VALID_ATTACK_TYPES))

    if len(probe_history) <= 0:
        return generate_payloads_phase1(
            waf_name,
            attack_type,
            num_of_payloads=num_payloads,
        )

    return generate_payloads_phase3(
        waf_name,
        attack_type,
        num_of_payloads=num_payloads,
        probe_history=probe_history,
    )


def _3_test_attack(
    domain: str,
    payloads: list[PayloadResult],
    check_harmful: bool = True,
) -> list[PayloadResult]:
    normalized_domain = _normalize_domain(domain)
    payload_results = list(payloads or [])

    session_id = dvwa.loginDVWA(base_url=normalized_domain)

    for item in payload_results:
        payload = item.payload
        attack_type = item.attack_type

        if check_harmful and payload and attack_type:
            if "xss" in attack_type.lower():
                harmfulness_result = evaluate_xss_payload(payload)
                if harmfulness_result:
                    item.is_harmful = not harmfulness_result.is_safe
            elif "sql" in attack_type.lower():
                harmfulness_result = evaluate_sql_payload(payload)
                if harmfulness_result:
                    item.is_harmful = len(harmfulness_result.harm_queries) > 0

        attack_func = dvwa.DVWA_ATTACK_FUNC.get(attack_type)
        if attack_func and payload:
            result = dvwa.attack(attack_type, payload, session_id, base_url=normalized_domain)
            item.is_bypassed = not result.blocked if result.blocked is not None else None
            item.status_code = result.status_code
        else:
            item.is_bypassed = None
            item.status_code = None

    return payload_results


def run_attack_pipeline(
    domain: str,
    attack_type: str,
    num_payloads: int = 5,
    payloads_history: Optional[list[PayloadResult]] = None,
    check_harmful: bool = True,
) -> dict[str, Any]:
    detect_result = _1_detect_waf(domain)
    generated_payloads = _2_generate_payload(
        waf_name=detect_result["waf_name"],
        attack_type=attack_type,
        num_payloads=num_payloads,
        payloads_history=payloads_history,
    )
    tested_payloads = _3_test_attack(
        domain=detect_result["domain"],
        payloads=generated_payloads,
        check_harmful=check_harmful,
    )

    return {
        "domain": detect_result["domain"],
        "waf_name": detect_result["waf_name"],
        "attack_type": attack_type,
        "payloads": tested_payloads,
        "stats": {
            "num_payloads": len(tested_payloads),
            "num_bypassed": len([payload for payload in tested_payloads if payload.is_bypassed]),
            "num_blocked": len([payload for payload in tested_payloads if payload.is_bypassed is False]),
            "num_harmful": len([payload for payload in tested_payloads if payload.is_harmful]),
        },
    }
