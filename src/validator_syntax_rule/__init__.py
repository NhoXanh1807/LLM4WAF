"""
Multi-WAF Rule Syntax Validator Package.

Offline validation for ModSecurity, Cloudflare, AWS WAF, and Naxsi rule syntax.

Part of the rule generation pipeline:
    [1] LLM + RAG -> generate rule
    [2] SyntaxValidator -> validate syntax (this package)
    [3] Agent 2 -> compare with existing rules
    [4] Semantic test -> manual/semi-auto testing

Usage:
    from validator_syntax_rule import SyntaxValidator, WAFType, validate_rule

    # Unified validator with auto-detect
    validator = SyntaxValidator()
    result = validator.validate(rule_string)

    # Specific WAF type
    result = validator.validate(rule_string, WAFType.MODSECURITY)

    # Quick validation
    result = validate_rule(rule_string, WAFType.CLOUDFLARE)

    # Individual validators
    from validator_syntax_rule import (
        validate_modsec_rule,
        validate_cloudflare_rule,
        validate_aws_waf_rule,
        validate_naxsi_rule,
    )
"""

from .base import (
    WAFType,
    ValidationResult,
    BaseValidator,
)

from .modsecurity import (
    ModSecurityValidator,
    validate_modsec_rule,
)

from .cloudflare import (
    CloudflareValidator,
    validate_cloudflare_rule,
)

from .aws_waf import (
    AWSWAFValidator,
    validate_aws_waf_rule,
)

from .naxsi import (
    NaxsiValidator,
    validate_naxsi_rule,
)

from .validator import (
    SyntaxValidator,
    validate_rule,
)


__all__ = [
    # Base classes
    "WAFType",
    "ValidationResult",
    "BaseValidator",
    # Unified validator
    "SyntaxValidator",
    "validate_rule",
    # Individual validators
    "ModSecurityValidator",
    "CloudflareValidator",
    "AWSWAFValidator",
    "NaxsiValidator",
    # Convenience functions
    "validate_modsec_rule",
    "validate_cloudflare_rule",
    "validate_aws_waf_rule",
    "validate_naxsi_rule",
]

__version__ = "1.0.0"
