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
try:
    # Try relative imports first (when imported as part of package)
    from .services import (
        chatgpt_completion,
        generate_payloads_from_domain_waf_info,
        generate_defend_rules_and_instructions,
        loginDVWA,
        attack_xss_dom,
        attack_xss_reflected,
        attack_xss_stored,
        attack_sql_injection,
        attack_sql_injection_blind
    )
except ImportError:
    # Fall back to absolute imports (when run directly with python3 app.py)
    from services import (
        chatgpt_completion,
        generate_payloads_from_domain_waf_info,
        generate_defend_rules_and_instructions,
        loginDVWA,
        attack_xss_dom,
        attack_xss_reflected,
        attack_xss_stored,
        attack_sql_injection,
        attack_sql_injection_blind
    )
from services.payload_service import generate_payloads_by_local_llm

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
    'generate_payloads_by_local_llm'
]
