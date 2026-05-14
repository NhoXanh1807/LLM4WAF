from typing import Optional
from wafw00f.main import WAFW00F
from models.dtos import PayloadResult
from services.generator import generate_payloads_phase1, generate_payloads_phase3
from services.sql_harmfulness_validator import evaluate_sql_payload
from external_services.xss_harmfulness_validator import evaluate_xss_payload
from external_services import dvwa


def _normalize_domain(domain: str) -> str:
    normalized_domain = str(domain or "").strip()
    if not normalized_domain:
        return None
    if not normalized_domain.startswith("http://") and not normalized_domain.startswith("https://"):
        normalized_domain = "http://" + normalized_domain
    return normalized_domain


def _1_detect_waf(domain: str) -> dict[str, str]:
    if not domain:
        raise ValueError("Missing 'domain' field")
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "http://" + domain
    print(f"[DETECT-WAF] Detecting domain: {domain}")
    waf = WAFW00F(domain)
    waf_info = waf.identwaf()
    waf_name = waf_info[0][0] if len(waf_info[0]) > 0 else "NO_WAF_INFORMATION"
    print(f"[DETECT-WAF] Detected: {waf_name}")
    return {
        "domain": domain,
        "waf_name": waf_name,
        "waf_info": waf_info,
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
    check_waf: bool = True,
) -> list[PayloadResult]:
    normalized_domain = _normalize_domain(domain)

    import tqdm
    if check_waf:
        session_id = dvwa.loginDVWA(base_url=normalized_domain)
    else:
        session_id = None
    for item in tqdm.tqdm(payloads, desc=f"[TEST-ATTACK] {len(payloads)} payloads on {domain}"):
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
                    
        if check_waf and payload and attack_type:
            attack_func = dvwa.DVWA_ATTACK_FUNC.get(attack_type)
            if attack_func:
                result = dvwa.attack(attack_type, payload, session_id, base_url=normalized_domain)
                item.is_bypassed = not result.blocked if result.blocked is not None else None
                item.status_code = result.status_code
            else:
                item.is_bypassed = None
                item.status_code = None
    
    bypassed = sum(1 for item in payloads if item.is_bypassed)
    harmful = sum(1 for item in payloads if item.is_harmful)
    bypassed_and_harmful = sum(1 for item in payloads if item.is_bypassed and item.is_harmful)
    bypassed_not_harmful = sum(1 for item in payloads if item.is_bypassed and item.is_harmful == False)
    not_bypassed_harmful = sum(1 for item in payloads if item.is_bypassed == False and item.is_harmful)
    not_bypassed_not_harmful = sum(1 for item in payloads if item.is_bypassed == False and item.is_harmful == False)
    print(f"\tBypassed: {bypassed}/{len(payloads)}, Harmful: {harmful}/{len(payloads)}")
    print(f"\tBypassed && Harmful: {bypassed_and_harmful}, Bypassed && Not-Harmful: {bypassed_not_harmful}")
    print(f"\tNot-Bypassed && Harmful: {not_bypassed_harmful}, Not-Bypassed && Not-Harmful: {not_bypassed_not_harmful}")
    
    return payloads

