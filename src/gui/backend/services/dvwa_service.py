"""
DVWA attack execution service
Handles login and all attack functions
"""

import re
import requests
try:
    from ..config.settings import (
        DVWA_BASE_URL,
        DVWA_USERNAME,
        DVWA_PASSWORD,
        DVWA_SECURITY_LEVEL
    )
except ImportError:
    from config.settings import (
        DVWA_BASE_URL,
        DVWA_USERNAME,
        DVWA_PASSWORD,
        DVWA_SECURITY_LEVEL
    )

from dataclasses import dataclass
@dataclass
class AttackResult:
    status_code: int
    blocked: bool


def loginDVWA():
    """
    Login to DVWA and return session ID

    Returns:
        str: PHPSESSID for authenticated requests
    """
    # Get PHPSESSID from login page
    response = requests.get(f"{DVWA_BASE_URL}/login.php")
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
        f"{DVWA_BASE_URL}/login.php",
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


def attack_xss_dom(payload, session_id) -> AttackResult:
    """
    Execute XSS DOM-Based attack

    Args:
        payload (str): XSS payload
        session_id (str): PHPSESSID from loginDVWA()

    Returns:
        dict: {status_code, blocked}
    """
    url = f"{DVWA_BASE_URL}/vulnerabilities/xss_d/?default={payload}"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=_check_blocked(response)
    )


def attack_xss_reflected(payload, session_id) -> AttackResult:
    """
    Execute XSS Reflected attack

    Args:
        payload (str): XSS payload
        session_id (str): PHPSESSID from loginDVWA()

    Returns:
        dict: {status_code, blocked}
    """
    url = f"{DVWA_BASE_URL}/vulnerabilities/xss_r/?name={payload}"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=_check_blocked(response)
    )


def attack_xss_stored(payload, session_id) -> AttackResult:
    """
    Execute XSS Stored attack

    Args:
        payload (str): XSS payload
        session_id (str): PHPSESSID from loginDVWA()

    Returns:
        dict: {status_code, blocked}
    """
    url = f"{DVWA_BASE_URL}/vulnerabilities/xss_s/"
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


def attack_sql_injection(payload, session_id) -> AttackResult:
    """
    Execute SQL Injection attack

    Args:
        payload (str): SQL injection payload
        session_id (str): PHPSESSID from loginDVWA()

    Returns:
        dict: {status_code, blocked}
    """
    url = f"{DVWA_BASE_URL}/vulnerabilities/sqli/?id={payload}&Submit=Submit"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=_check_blocked(response)
    )


def attack_sql_injection_blind(payload, session_id) -> AttackResult:
    """
    Execute Blind SQL Injection attack

    Args:
        payload (str): SQL injection payload
        session_id (str): PHPSESSID from loginDVWA()

    Returns:
        dict: {status_code, blocked}
    """
    url = f"{DVWA_BASE_URL}/vulnerabilities/sqli_blind/?id={payload}&Submit=Submit"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=_check_blocked(response)
    )
