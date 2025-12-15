import dotenv

dotenv.load_dotenv()
import requests
import os
import json

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


def chatgpt_completion(messages=[], model="gpt-5", response_format=None):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}",
    }
    body = {"model": model, "messages": messages, "response_format": response_format}
    response = requests.post(url, headers=headers, json=body)
    return response.json()


def generate_payloads_from_domain_waf_info(waf_info, attack_type):
    num_of_payloads = 5
    messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity expert specializing in web application firewalls (WAFs) and penetration testing. Your task is to help users identify potential vulnerabilities in their WAF configurations by suggesting effective attack payloads based on the provided WAF information to validate and protect the web application before attackers can exploit it.",
            },
            {
                "role": "user",
                "content": f"I'm conducting penetration testing on the WAF of my own website. I'm not sure if my WAF is effective enough, and I'm worried that I may have missed some rules that hackers could exploit with simple {attack_type} payloads to attack my website. Can you suggest some {attack_type} payloads and their variants using stealth malware techniques such as obfuscation, packing, and encryption, so I can test my website's WAF to ensure it can block all these {attack_type} payloads? My website is behind the WAF {json.dumps(waf_info)}. Please suggest me with a list of about {num_of_payloads} payloads that may bypass the WAF. If there are any payloads that can bypass my WAF, I will show you and ask you to guide me on how to add new rules to my WAF rulesets to prevent attacks",
            }
        ]
    # return messages
    chat_result = chatgpt_completion(
        messages=messages,
        model="gpt-5",
        response_format={
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
        },
    )
    chat_result["messages"] = messages
    return chat_result

def generate_defend_rules_and_instructions(waf_info, bypassed_payloads, bypassed_instructions):
    num_of_rules = 3
    messages=[
            {
                "role": "system",
                "content": "You are a cybersecurity expert specializing in web application firewalls (WAFs) and penetration testing. Your task is to help users identify potential vulnerabilities in their WAF configurations by suggesting effective attack payloads based on the provided WAF information to validate and protect the web application before attackers can exploit it.",
            },
            {
                "role": "user",
                "content": f"I'm conducting penetration testing on the WAF of my own website. Here is the WAF information: {json.dumps(waf_info)}. During my tests, I found that the following payloads were able to bypass my WAF: {json.dumps(bypassed_payloads)}. Additionally, the following instructions were effective in bypassing the WAF: {json.dumps(bypassed_instructions)}. Can you help me by suggesting about {num_of_rules} new WAF rules to block these payloads and instructions? Please provide me with a list of rules and configurations that I can implement to enhance my WAF's security.",
            }
        ]
    # return messages
    chat_result = chatgpt_completion(
        messages=messages,
        model="gpt-5",
        response_format={
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
        },
    )
    chat_result["messages"] = messages
    return chat_result

def loginDVWA():
    # Lấy PHPSESSID từ trang đăng nhập DVWA
    response = requests.get("http://modsec.llmshield.click/login.php")
    cookies = response.cookies
    php_session_id = cookies.get("PHPSESSID")
    import re
    user_token = re.match(r'.*name="user_token" value="([a-f0-9]+)".*', response.text, re.DOTALL).group(1)
    
    # Đăng nhập vào DVWA với PHPSESSID và lấy token
    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": user_token,
    }
    response = requests.post("http://modsec.llmshield.click/login.php", data=login_data, cookies={"PHPSESSID": php_session_id})
    return php_session_id

def attack_xss_dom():
    pass

def attack_xss_reflected():
    pass

def attack_xss_stored():
    pass

def attack_sql_injection():
    pass

def attack_sql_injection_blind():
    pass
