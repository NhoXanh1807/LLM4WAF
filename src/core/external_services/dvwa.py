
import os
import re
import requests
from dtos import AttackResult

# Flexible imports for different execution contexts
DVWA_BASE_URL = None
DVWA_USERNAME = None
DVWA_PASSWORD = None
DVWA_SECURITY_LEVEL = None
from settings import (
    DVWA_BASE_URL,
    DVWA_USERNAME,
    DVWA_PASSWORD,
    DVWA_SECURITY_LEVEL
)

# Default values if imports failed
if DVWA_BASE_URL is None:
    DVWA_BASE_URL = os.getenv("DVWA_BASE_URL", "http://localhost")
if DVWA_USERNAME is None:
    DVWA_USERNAME = os.getenv("DVWA_USERNAME", "admin")
if DVWA_PASSWORD is None:
    DVWA_PASSWORD = os.getenv("DVWA_PASSWORD", "password")
if DVWA_SECURITY_LEVEL is None:
    DVWA_SECURITY_LEVEL = os.getenv("DVWA_SECURITY_LEVEL", "low")


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


# Map attack types to functions
DVWA_ATTACK_FUNC = {
    "xss_dom": attack_xss_dom,
    "xss_reflected": attack_xss_reflected,
    "xss_stored": attack_xss_stored,
    "sql_injection": attack_sql_injection,
    "sql_injection_blind": attack_sql_injection_blind,
}

VALID_ATTACK_TYPES = [
    "xss_dom",
    "xss_reflected", 
    "xss_stored", 
    "sql_injection", 
    "sql_injection_blind"
]

def attack(type : str, payload : str, session_id : str, base_url : str = None) -> AttackResult:
    func = DVWA_ATTACK_FUNC.get(type)
    if func:
        try:
            return func(payload, session_id, base_url=base_url)
        except Exception as e:
            print(f"Error executing attack {type}: {str(e)}")
            return AttackResult(status_code=0, blocked=None)
    else:
        raise ValueError(f"Invalid attack type: {type}")