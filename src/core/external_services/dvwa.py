
import os
import re
import requests
from models.dtos import AttackResult

# Flexible imports for different execution contexts

# Default values if imports failed
_SESSION_IDS = {}

def loginDVWA(base_url, username="admin", password="password"):
    """
    Login to DVWA and return session ID

    Returns:
        str: PHPSESSID for authenticated requests
    """
    _base = base_url.rstrip("/")
    if _base in _SESSION_IDS:
        return _SESSION_IDS[_base]
    
    print(f"[DVWA] Logging in to {_base}...")
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
        "username": username,
        "password": password,
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
    _SESSION_IDS[_base] = php_session_id
    return php_session_id


def attack_xss_dom(payload, session_id, base_url=None, security_level="low") -> AttackResult:
    _base = base_url.rstrip("/")
    url = f"{_base}/vulnerabilities/xss_d/?default={payload}"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": security_level}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=response.status_code == 403
    )


def attack_xss_reflected(payload, session_id, base_url=None, security_level="low") -> AttackResult:
    _base = base_url.rstrip("/")
    url = f"{_base}/vulnerabilities/xss_r/?name={payload}"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": security_level    }
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=response.status_code == 403
    )


def attack_xss_stored(payload, session_id, base_url=None, security_level="low") -> AttackResult:
    _base = base_url.rstrip("/")
    url = f"{_base}/vulnerabilities/xss_s/"
    data = {
        "txtName": payload,
        "mtxMessage": "test",
        "btnSign": "Sign Guestbook"
    }
    response = requests.post(
        url,
        data=data,
        cookies={"PHPSESSID": session_id, "security": security_level}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=response.status_code == 403
    )


def attack_sql_injection(payload, session_id, base_url=None, security_level="low") -> AttackResult:
    _base = base_url.rstrip("/")
    url = f"{_base}/vulnerabilities/sqli/?id={payload}&Submit=Submit"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": security_level}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=response.status_code == 403
    )


def attack_sql_injection_blind(payload, session_id, base_url=None, security_level="low") -> AttackResult:
    _base = base_url.rstrip("/")
    url = f"{_base}/vulnerabilities/sqli_blind/?id={payload}&Submit=Submit"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": security_level}
    )
    return AttackResult(
        status_code=response.status_code,
        blocked=response.status_code == 403
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

def attack(type : str, payload : str, session_id : str, base_url : str = None, security_level : str ="low") -> AttackResult:
    func = DVWA_ATTACK_FUNC.get(type)
    if func:
        try:
            return func(payload, session_id, base_url=base_url, security_level=security_level)
        except Exception as e:
            print(f"Error executing attack {type}: {str(e)}")
            return AttackResult(status_code=0, blocked=None)
    else:
        raise ValueError(f"Invalid attack type: {type}")