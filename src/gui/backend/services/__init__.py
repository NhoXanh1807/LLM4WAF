"""
Services module for LLMShield backend
"""

from .llm_service import chatgpt_completion
from .payload_service import generate_payloads_from_domain_waf_info
from .defense_service import generate_defend_rules_and_instructions
from .dvwa_service import (
    loginDVWA,
    attack_xss_dom,
    attack_xss_reflected,
    attack_xss_stored,
    attack_sql_injection,
    attack_sql_injection_blind
)
