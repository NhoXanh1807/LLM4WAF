"""
Unified Multi-WAF Syntax Validator.

This module provides module-level helpers for validating rules
from multiple WAF types with automatic detection.
"""

import json
from typing import Optional

from .aws_waf import AWSWAFValidator
from .base import BaseValidator, ValidationResult, WAFType
from .cloudflare import CloudflareValidator
from .modsecurity import ModSecurityValidator
from .naxsi import NaxsiValidator


VALIDATORS: dict[WAFType, BaseValidator] = {
    WAFType.MODSECURITY: ModSecurityValidator(),
    WAFType.CLOUDFLARE: CloudflareValidator(),
    WAFType.AWS_WAF: AWSWAFValidator(),
    WAFType.NAXSI: NaxsiValidator(),
}


def detect_waf_type(rule: str) -> Optional[WAFType]:
    """
    Detect WAF type from rule syntax.

    Args:
        rule: The rule string

    Returns:
        Detected WAFType or None if cannot detect
    """
    rule = rule.strip()

    if rule.startswith('Sec') or '@rx' in rule or '@pm' in rule:
        return WAFType.MODSECURITY

    rule_lower = rule.lower()
    if (
        rule_lower.startswith('mainrule')
        or rule_lower.startswith('basicrule')
        or rule_lower.startswith('checkrule')
    ):
        return WAFType.NAXSI

    if rule.startswith('{'):
        try:
            obj = json.loads(rule)
            aws_keys = {
                'Statement', 'Rules', 'ByteMatchStatement',
                'SqliMatchStatement', 'XssMatchStatement',
                'FieldToMatch', 'TextTransformations',
                'GeoMatchStatement', 'RateBasedStatement',
            }
            if any(key in str(obj) for key in aws_keys):
                return WAFType.AWS_WAF
        except json.JSONDecodeError:
            pass

    cf_indicators = ['http.', 'ip.src', 'cf.', 'ssl.', ' contains ', ' matches ']
    if any(indicator in rule.lower() for indicator in cf_indicators):
        return WAFType.CLOUDFLARE

    return None


def validate(rule: str, waf_type: Optional[WAFType] = None) -> ValidationResult:
    if not waf_type:
        waf_type = detect_waf_type(rule)
        if not waf_type:
            return ValidationResult(
                is_valid=False,
                error_message="Cannot auto-detect WAF type. Please specify waf_type parameter."
            )
    validator = VALIDATORS.get(waf_type)
    if not validator:
        return ValidationResult(
            is_valid=False,
            error_message=f"Unsupported WAF type: {waf_type}"
        )
    return validator.validate(rule)

