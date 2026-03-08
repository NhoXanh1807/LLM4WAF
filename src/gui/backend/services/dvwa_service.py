"""
DVWA attack execution service
Handles login and all attack functions

IMPORTANT: This module now supports exploit verification!
Use the `_verified` suffix functions or `verify_exploit` parameter
to get accurate exploit status (not just WAF bypass status).

Attack Result States:
    - BLOCKED: WAF blocked the request
    - PASSED_NO_EFFECT: Bypassed WAF but payload didn't exploit
    - EXPLOITED: Successfully exploited DVWA
"""

import os
import re
import requests
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum

# Flexible imports for different execution contexts
DVWA_BASE_URL = None
DVWA_USERNAME = None
DVWA_PASSWORD = None
DVWA_SECURITY_LEVEL = None

try:
    from ..config.settings import (
        DVWA_BASE_URL,
        DVWA_USERNAME,
        DVWA_PASSWORD,
        DVWA_SECURITY_LEVEL
    )
except ImportError:
    try:
        from config.settings import (
            DVWA_BASE_URL,
            DVWA_USERNAME,
            DVWA_PASSWORD,
            DVWA_SECURITY_LEVEL
        )
    except ImportError:
        pass

# Default values if imports failed
if DVWA_BASE_URL is None:
    DVWA_BASE_URL = os.getenv("DVWA_BASE_URL", "http://localhost")
if DVWA_USERNAME is None:
    DVWA_USERNAME = os.getenv("DVWA_USERNAME", "admin")
if DVWA_PASSWORD is None:
    DVWA_PASSWORD = os.getenv("DVWA_PASSWORD", "password")
if DVWA_SECURITY_LEVEL is None:
    DVWA_SECURITY_LEVEL = os.getenv("DVWA_SECURITY_LEVEL", "low")

# Import exploit verifier (flexible for different execution contexts)
VERIFIER_AVAILABLE = False
ExploitVerifier = None
ExploitStatus = None
ExploitResult = None

try:
    from .exploit_verifier import ExploitVerifier, ExploitStatus, ExploitResult
    VERIFIER_AVAILABLE = True
except ImportError:
    try:
        from exploit_verifier import ExploitVerifier, ExploitStatus, ExploitResult
        VERIFIER_AVAILABLE = True
    except ImportError:
        pass


class AttackStatus(Enum):
    """Attack result status."""
    BLOCKED = "blocked"
    PASSED_NO_EFFECT = "passed_no_effect"
    EXPLOITED = "exploited"
    ERROR = "error"


@dataclass
class AttackResult:
    """Basic attack result (backward compatible)."""
    status_code: int
    blocked: bool


@dataclass
class VerifiedAttackResult:
    """
    Enhanced attack result with exploit verification.

    Attributes:
        status_code: HTTP response status code
        status: Attack status (BLOCKED, PASSED_NO_EFFECT, EXPLOITED, ERROR)
        blocked: True if WAF blocked the request
        bypassed: True if request bypassed WAF (regardless of exploit success)
        exploited: True if payload successfully exploited DVWA
        evidence: Evidence of exploitation (if exploited)
        payload: The payload that was tested
        attack_type: Type of attack
    """
    status_code: int
    status: AttackStatus
    blocked: bool
    bypassed: bool
    exploited: bool
    evidence: Optional[str] = None
    payload: str = ""
    attack_type: str = ""
    verification_details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "status_code": self.status_code,
            "status": self.status.value,
            "blocked": self.blocked,
            "bypassed": self.bypassed,
            "exploited": self.exploited,
            "evidence": self.evidence,
            "payload": self.payload,
            "attack_type": self.attack_type,
        }


def loginDVWA(base_url=None):
    """
    Login to DVWA and return session ID

    Returns:
        str: PHPSESSID for authenticated requests
    """
    _base = (base_url or DVWA_BASE_URL).rstrip("/")
    # Get PHPSESSID from login page
    response = requests.get(f"{_base}/login.php")
    cookies = response.cookies
    php_session_id = cookies.get("PHPSESSID")

    # Try to extract user_token (CSRF token) if exists
    token_match = re.search(
        r'name=["\']user_token["\'] value=["\']([a-f0-9]+)["\']',
        response.text
    )

    # Prepare login data
    login_data = {
        "username": DVWA_USERNAME,
        "password": DVWA_PASSWORD,
        "Login": "Login",
    }

    # Add user_token only if found
    if token_match:
        login_data["user_token"] = token_match.group(1)

    # Perform login
    response = requests.post(
        f"{_base}/login.php",
        data=login_data,
        cookies={"PHPSESSID": php_session_id}
    )

    return php_session_id


def _check_blocked(response):
    """
    Check if request was blocked by WAF

    Args:
        response: requests.Response object

    Returns:
        bool: True if blocked, False if bypassed
    """
    return "ModSecurity" in response.text or response.status_code == 403


def attack_xss_dom(payload, session_id, base_url=None) -> AttackResult:
    """
    Execute XSS DOM-Based attack

    Args:
        payload (str): XSS payload
        session_id (str): PHPSESSID from loginDVWA()

    Returns:
        dict: {status_code, blocked}
    """
    _base = (base_url or DVWA_BASE_URL).rstrip("/")
    url = f"{_base}/vulnerabilities/xss_d/?default={payload}"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=_check_blocked(response)
    )


def attack_xss_reflected(payload, session_id, base_url=None) -> AttackResult:
    """
    Execute XSS Reflected attack

    Args:
        payload (str): XSS payload
        session_id (str): PHPSESSID from loginDVWA()

    Returns:
        dict: {status_code, blocked}
    """
    _base = (base_url or DVWA_BASE_URL).rstrip("/")
    url = f"{_base}/vulnerabilities/xss_r/?name={payload}"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=_check_blocked(response)
    )


def attack_xss_stored(payload, session_id, base_url=None) -> AttackResult:
    """
    Execute XSS Stored attack

    Args:
        payload (str): XSS payload
        session_id (str): PHPSESSID from loginDVWA()

    Returns:
        dict: {status_code, blocked}
    """
    _base = (base_url or DVWA_BASE_URL).rstrip("/")
    url = f"{_base}/vulnerabilities/xss_s/"
    data = {
        "txtName": payload,
        "mtxMessage": "test",
        "btnSign": "Sign Guestbook"
    }
    response = requests.post(
        url,
        data=data,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=_check_blocked(response)
    )


def attack_sql_injection(payload, session_id, base_url=None) -> AttackResult:
    """
    Execute SQL Injection attack

    Args:
        payload (str): SQL injection payload
        session_id (str): PHPSESSID from loginDVWA()

    Returns:
        dict: {status_code, blocked}
    """
    _base = (base_url or DVWA_BASE_URL).rstrip("/")
    url = f"{_base}/vulnerabilities/sqli/?id={payload}&Submit=Submit"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=_check_blocked(response)
    )


def attack_sql_injection_blind(payload, session_id, base_url=None) -> AttackResult:
    """
    Execute Blind SQL Injection attack

    Args:
        payload (str): SQL injection payload
        session_id (str): PHPSESSID from loginDVWA()

    Returns:
        dict: {status_code, blocked}
    """
    _base = (base_url or DVWA_BASE_URL).rstrip("/")
    url = f"{_base}/vulnerabilities/sqli_blind/?id={payload}&Submit=Submit"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=_check_blocked(response)
    )


# =============================================================================
# VERIFIED ATTACK FUNCTIONS
# These functions verify if the payload actually exploited DVWA
# =============================================================================

def _convert_exploit_result(result, payload: str, attack_type: str) -> VerifiedAttackResult:
    """Convert ExploitResult to VerifiedAttackResult."""
    if not VERIFIER_AVAILABLE or result is None:
        return VerifiedAttackResult(
            status_code=0,
            status=AttackStatus.ERROR,
            blocked=False,
            bypassed=False,
            exploited=False,
            payload=payload,
            attack_type=attack_type,
            verification_details={"error": "Verifier not available"},
        )

    status_map = {
        ExploitStatus.BLOCKED: AttackStatus.BLOCKED,
        ExploitStatus.PASSED_NO_EFFECT: AttackStatus.PASSED_NO_EFFECT,
        ExploitStatus.EXPLOITED: AttackStatus.EXPLOITED,
        ExploitStatus.ERROR: AttackStatus.ERROR,
    }

    return VerifiedAttackResult(
        status_code=result.status_code,
        status=status_map.get(result.status, AttackStatus.ERROR),
        blocked=result.is_blocked,
        bypassed=result.bypassed_waf,
        exploited=result.is_exploited,
        evidence=result.evidence,
        payload=payload,
        attack_type=attack_type,
        verification_details=result.verification_details,
    )


def attack_xss_reflected_verified(payload: str, session_id: str) -> VerifiedAttackResult:
    """
    Execute XSS Reflected attack WITH exploit verification.

    Returns VerifiedAttackResult with:
        - blocked: WAF blocked the request
        - bypassed: Request went through WAF
        - exploited: Payload actually reflected in response (XSS works)

    Args:
        payload: XSS payload
        session_id: PHPSESSID from loginDVWA()

    Returns:
        VerifiedAttackResult with full verification
    """
    if not VERIFIER_AVAILABLE:
        # Fallback to basic check
        basic_result = attack_xss_reflected(payload, session_id)
        return VerifiedAttackResult(
            status_code=basic_result.status_code,
            status=AttackStatus.BLOCKED if basic_result.blocked else AttackStatus.PASSED_NO_EFFECT,
            blocked=basic_result.blocked,
            bypassed=not basic_result.blocked,
            exploited=False,  # Cannot verify without verifier
            payload=payload,
            attack_type="xss_reflected",
        )

    verifier = ExploitVerifier(session_id)
    result = verifier.verify_xss_reflected(payload)
    return _convert_exploit_result(result, payload, "xss_reflected")


def attack_xss_dom_verified(payload: str, session_id: str) -> VerifiedAttackResult:
    """
    Execute XSS DOM attack WITH exploit verification.

    Args:
        payload: XSS payload
        session_id: PHPSESSID from loginDVWA()

    Returns:
        VerifiedAttackResult with full verification
    """
    if not VERIFIER_AVAILABLE:
        basic_result = attack_xss_dom(payload, session_id)
        return VerifiedAttackResult(
            status_code=basic_result.status_code,
            status=AttackStatus.BLOCKED if basic_result.blocked else AttackStatus.PASSED_NO_EFFECT,
            blocked=basic_result.blocked,
            bypassed=not basic_result.blocked,
            exploited=False,
            payload=payload,
            attack_type="xss_dom",
        )

    verifier = ExploitVerifier(session_id)
    result = verifier.verify_xss_dom(payload)
    return _convert_exploit_result(result, payload, "xss_dom")


def attack_xss_stored_verified(payload: str, session_id: str) -> VerifiedAttackResult:
    """
    Execute XSS Stored attack WITH exploit verification.

    Args:
        payload: XSS payload
        session_id: PHPSESSID from loginDVWA()

    Returns:
        VerifiedAttackResult with full verification
    """
    if not VERIFIER_AVAILABLE:
        basic_result = attack_xss_stored(payload, session_id)
        return VerifiedAttackResult(
            status_code=basic_result.status_code,
            status=AttackStatus.BLOCKED if basic_result.blocked else AttackStatus.PASSED_NO_EFFECT,
            blocked=basic_result.blocked,
            bypassed=not basic_result.blocked,
            exploited=False,
            payload=payload,
            attack_type="xss_stored",
        )

    verifier = ExploitVerifier(session_id)
    result = verifier.verify_xss_stored(payload)
    return _convert_exploit_result(result, payload, "xss_stored")


def attack_sqli_verified(payload: str, session_id: str) -> VerifiedAttackResult:
    """
    Execute SQL Injection attack WITH exploit verification.

    Verifies if the payload actually leaked database data.

    Args:
        payload: SQL injection payload
        session_id: PHPSESSID from loginDVWA()

    Returns:
        VerifiedAttackResult with full verification
    """
    if not VERIFIER_AVAILABLE:
        basic_result = attack_sql_injection(payload, session_id)
        return VerifiedAttackResult(
            status_code=basic_result.status_code,
            status=AttackStatus.BLOCKED if basic_result.blocked else AttackStatus.PASSED_NO_EFFECT,
            blocked=basic_result.blocked,
            bypassed=not basic_result.blocked,
            exploited=False,
            payload=payload,
            attack_type="sqli",
        )

    verifier = ExploitVerifier(session_id)
    result = verifier.verify_sqli(payload)
    return _convert_exploit_result(result, payload, "sqli")


def attack_sqli_blind_verified(payload: str, session_id: str) -> VerifiedAttackResult:
    """
    Execute Blind SQL Injection attack WITH exploit verification.

    Verifies using time-based and boolean-based detection.

    Args:
        payload: SQL injection payload
        session_id: PHPSESSID from loginDVWA()

    Returns:
        VerifiedAttackResult with full verification
    """
    if not VERIFIER_AVAILABLE:
        basic_result = attack_sql_injection_blind(payload, session_id)
        return VerifiedAttackResult(
            status_code=basic_result.status_code,
            status=AttackStatus.BLOCKED if basic_result.blocked else AttackStatus.PASSED_NO_EFFECT,
            blocked=basic_result.blocked,
            bypassed=not basic_result.blocked,
            exploited=False,
            payload=payload,
            attack_type="sqli_blind",
        )

    verifier = ExploitVerifier(session_id)
    result = verifier.verify_sqli_blind(payload)
    return _convert_exploit_result(result, payload, "sqli_blind")


def execute_attack_verified(
    payload: str,
    attack_type: str,
    session_id: str
) -> VerifiedAttackResult:
    """
    Execute any attack type with verification.

    Args:
        payload: Attack payload
        attack_type: Type of attack (xss_reflected, xss_dom, xss_stored, sqli, sqli_blind)
        session_id: PHPSESSID from loginDVWA()

    Returns:
        VerifiedAttackResult with full verification
    """
    attack_type = attack_type.lower().replace("-", "_").replace(" ", "_")

    attack_functions = {
        "xss_reflected": attack_xss_reflected_verified,
        "xss_r": attack_xss_reflected_verified,
        "xss_dom": attack_xss_dom_verified,
        "xss_d": attack_xss_dom_verified,
        "xss_stored": attack_xss_stored_verified,
        "xss_s": attack_xss_stored_verified,
        "sqli": attack_sqli_verified,
        "sql_injection": attack_sqli_verified,
        "sqli_blind": attack_sqli_blind_verified,
        "sql_injection_blind": attack_sqli_blind_verified,
    }

    attack_func = attack_functions.get(attack_type)
    if not attack_func:
        return VerifiedAttackResult(
            status_code=0,
            status=AttackStatus.ERROR,
            blocked=False,
            bypassed=False,
            exploited=False,
            payload=payload,
            attack_type=attack_type,
            verification_details={"error": f"Unknown attack type: {attack_type}"},
        )

    return attack_func(payload, session_id)


def execute_attacks_verified(
    payloads: list[dict],
    session_id: str
) -> list[VerifiedAttackResult]:
    """
    Execute multiple attacks with verification.

    Args:
        payloads: List of {"payload": "...", "attack_type": "..."}
        session_id: PHPSESSID from loginDVWA()

    Returns:
        List of VerifiedAttackResult
    """
    results = []
    for item in payloads:
        result = execute_attack_verified(
            payload=item.get("payload", ""),
            attack_type=item.get("attack_type", "xss_reflected"),
            session_id=session_id
        )
        results.append(result)
    return results


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_truly_exploited_payloads(
    payloads: list[dict],
    session_id: str
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Categorize payloads into blocked, bypassed-no-effect, and exploited.

    This is the CORRECT way to evaluate payload effectiveness!

    Args:
        payloads: List of {"payload": "...", "attack_type": "..."}
        session_id: PHPSESSID from loginDVWA()

    Returns:
        Tuple of (blocked_payloads, bypassed_no_effect, exploited_payloads)
    """
    blocked = []
    bypassed_no_effect = []
    exploited = []

    for item in payloads:
        result = execute_attack_verified(
            payload=item.get("payload", ""),
            attack_type=item.get("attack_type", "xss_reflected"),
            session_id=session_id
        )

        payload_info = {
            **item,
            "status": result.status.value,
            "evidence": result.evidence,
        }

        if result.blocked:
            blocked.append(payload_info)
        elif result.exploited:
            exploited.append(payload_info)
        else:
            bypassed_no_effect.append(payload_info)

    return blocked, bypassed_no_effect, exploited


def print_attack_summary(results: list[VerifiedAttackResult]):
    """Print summary of attack results."""
    blocked = sum(1 for r in results if r.blocked)
    bypassed = sum(1 for r in results if r.bypassed)
    exploited = sum(1 for r in results if r.exploited)
    bypassed_no_effect = bypassed - exploited

    print(f"\n{'='*50}")
    print("ATTACK RESULTS SUMMARY")
    print(f"{'='*50}")
    print(f"Total attacks:      {len(results)}")
    print(f"Blocked by WAF:     {blocked}")
    print(f"Bypassed WAF:       {bypassed}")
    print(f"  - Exploited:      {exploited} ⚠️  CRITICAL")
    print(f"  - No effect:      {bypassed_no_effect}")
    print(f"{'='*50}\n")
