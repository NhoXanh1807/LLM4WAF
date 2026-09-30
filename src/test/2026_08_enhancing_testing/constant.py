
SEEDS = [42, 123, 2024, 777, 999]

WAF_NAMES = ["ModSecurity", "Naxsi", "Cloudflare", "AWS"]

VALID_ATTACK_TYPES = [
    "xss_dom",
    "xss_reflected",
    "xss_stored",
    "sql_injection",
    "sql_injection_blind",
]

WAF_DOMAINS = {
    "ModSecurity": "http://modsec.llmshield.click",
    "Naxsi": "http://naxsi.llmshield.click",
    "Cloudflare": "http://llmshield.click",
    "AWS": "http://aws.llmshield.click",
}