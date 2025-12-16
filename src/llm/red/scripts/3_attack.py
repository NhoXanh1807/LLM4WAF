
import requests
import re
import json
import tqdm


XSS_payloads_path = "/home/llm/output/XSS_generated_payloads.txt"
SQLi_payloads_path = "/home/llm/output/SQL_Injection_generated_payloads.txt"

with open(XSS_payloads_path, "r") as f:
    content = f.read()
    xss_payloads = [line.strip() for line in content.split("model\n") if line.strip()]
with open(SQLi_payloads_path, "r") as f:
    content = f.read()
    sqli_payloads = [line.strip() for line in content.split("model\n") if line.strip()]

with open("/home/llm/output/SQL_Injection_generated_payloads.json", "w") as f:
    json.dump(sqli_payloads, f, indent=2)
with open("/home/llm/output/XSS_generated_payloads.json", "w") as f:
    json.dump(xss_payloads, f, indent=2)



DVWA_BASE_URL = "http://modsec.llmshield.click"

def loginDVWA():
    DVWA_USERNAME = "admin"
    DVWA_PASSWORD = "password"
    
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

def test_XSS(payload, session_id):
    VULN_PAGE = f"{DVWA_BASE_URL}/vulnerabilities/xss_r/"
    headers = {
        "Cookie": f"PHPSESSID={session_id}; security=low"
    }
    data = {
        "name": payload,
        "submit": "Submit"
    }
    response = requests.post(VULN_PAGE, data=data, headers=headers)
    return response.status_code
    
def text_SQLi(payload, session_id):
    VULN_PAGE = f"{DVWA_BASE_URL}/vulnerabilities/sqli/"
    headers = {
        "Cookie": f"PHPSESSID={session_id}; security=low"
    }
    data = {
        "id": payload,
        "Submit": "Submit"
    }
    response = requests.post(VULN_PAGE, data=data, headers=headers)
    return response.status_code

if __name__ == "__main__":
    session_id = loginDVWA()
    print(f"Logged in with session ID: {session_id}")

    result = {
        "XSS": {
            "blocked": [],
            "bypassed": []
        },
        "SQLi": {
            "blocked": [],
            "bypassed": []
        }
    }
    for payload in tqdm.tqdm(xss_payloads, desc="Testing XSS payloads"):
        status_code = test_XSS(payload, session_id)
        if status_code == 200:
            result["XSS"]["bypassed"].append(payload)
        else:
            result["XSS"]["blocked"].append(payload)
    for payload in tqdm.tqdm(sqli_payloads, desc="Testing SQLi payloads"):
        status_code = text_SQLi(payload, session_id)
        if status_code == 200:
            result["SQLi"]["bypassed"].append(payload)
        else:
            result["SQLi"]["blocked"].append(payload)
    with open("/home/llm/output/attack_results.json", "w") as f:
        json.dump(result, f, indent=2)
    print("XSS total payloads tested:", len(xss_payloads))
    print("bypassed:", len(result["XSS"]["bypassed"]))
    print("blocked:", len(result["XSS"]["blocked"]))
    
    print("SQLi total payloads tested:", len(sqli_payloads))
    print("bypassed:", len(result["SQLi"]["bypassed"]))
    print("blocked:", len(result["SQLi"]["blocked"]))