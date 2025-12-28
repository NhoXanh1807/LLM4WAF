"""
Legacy utils module for backwards compatibility

This module re-exports all functions from the refactored services.
Existing code (app.py, CLI) can continue importing from utils without changes.

New code should import directly from services:
    from services.payload_service import generate_payloads_from_domain_waf_info
    from services.dvwa_service import loginDVWA, attack_xss_dom
"""

# Import and re-export all functions
# Handle both direct execution (python3 app.py) and package imports
# try:
#     # Try relative imports first (when imported as part of package)
#     from .services import (
#         chatgpt_completion,
#         generate_payloads_from_domain_waf_info,
#         generate_defend_rules_and_instructions,
#         loginDVWA,
#         attack_xss_dom,
#         attack_xss_reflected,
#         attack_xss_stored,
#         attack_sql_injection,
#         attack_sql_injection_blind
#     )
# except ImportError:
#     # Fall back to absolute imports (when run directly with python3 app.py)
#     from services import (
#         chatgpt_completion,
#         generate_payloads_from_domain_waf_info,
#         generate_defend_rules_and_instructions,
#         loginDVWA,
#         attack_xss_dom,
#         attack_xss_reflected,
#         attack_xss_stored,
#         attack_sql_injection,
#         attack_sql_injection_blind
#     )
from .services.payload_service import *
from .services.defense_service import *
from .services.dvwa_service import *
from .services.llm_service import *

# Re-export for backwards compatibility
__all__ = [
    'chatgpt_completion',
    'generate_payloads_from_domain_waf_info',
    'generate_defend_rules_and_instructions',
    'loginDVWA',
    'attack_xss_dom',
    'attack_xss_reflected',
    'attack_xss_stored',
    'attack_sql_injection',
    'attack_sql_injection_blind',
    'generate_payload_phase1',
    'generate_payload_phase3'
]

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

def attack(type : str, payload : str, session_id : str) -> AttackResult:
    func = DVWA_ATTACK_FUNC.get(type)
    if func:
        return func(payload, session_id)
    else:
        raise ValueError(f"Invalid attack type: {type}")