"""
Unified Multi-WAF Syntax Validator.

This module provides a unified interface for validating rules
from multiple WAF types with automatic detection.
"""

import json
from typing import Optional

from .base import BaseValidator, ValidationResult, WAFType
from .modsecurity import ModSecurityValidator
from .cloudflare import CloudflareValidator
from .aws_waf import AWSWAFValidator
from .naxsi import NaxsiValidator


class SyntaxValidator:
    """
    Unified syntax validator for multiple WAF types.

    Automatically detects WAF type or validates for specific type.

    Supported WAF types:
    - ModSecurity (SecRule syntax)
    - Cloudflare (wirefilter expressions)
    - AWS WAF (JSON format)
    - Naxsi (MainRule/BasicRule/CheckRule)

    Usage:
        validator = SyntaxValidator()

        # Auto-detect WAF type
        result = validator.validate(rule_string)

        # Specific WAF type
        result = validator.validate(rule_string, WAFType.MODSECURITY)

        # Batch validation
        results = validator.validate_batch(rules, WAFType.CLOUDFLARE)
    """

    def __init__(self):
        """Initialize all WAF validators."""
        self.validators: dict[WAFType, BaseValidator] = {
            WAFType.MODSECURITY: ModSecurityValidator(),
            WAFType.CLOUDFLARE: CloudflareValidator(),
            WAFType.AWS_WAF: AWSWAFValidator(),
            WAFType.NAXSI: NaxsiValidator(),
        }

    def validate(
        self,
        rule: str,
        waf_type: Optional[WAFType] = None
    ) -> ValidationResult:
        """
        Validate a rule.

        Args:
            rule: The rule string to validate
            waf_type: Optional WAF type. If None, auto-detect.

        Returns:
            ValidationResult with validation status and details
        """
        if waf_type:
            validator = self.validators.get(waf_type)
            if not validator:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Unsupported WAF type: {waf_type}"
                )
            return validator.validate(rule)

        # Auto-detect WAF type
        detected_type = self.detect_waf_type(rule)
        if detected_type:
            return self.validators[detected_type].validate(rule)

        return ValidationResult(
            is_valid=False,
            error_message="Cannot auto-detect WAF type. Please specify waf_type parameter."
        )

    def detect_waf_type(self, rule: str) -> Optional[WAFType]:
        """
        Detect WAF type from rule syntax.

        Args:
            rule: The rule string

        Returns:
            Detected WAFType or None if cannot detect
        """
        rule = rule.strip()

        # ModSecurity detection
        if rule.startswith('Sec') or '@rx' in rule or '@pm' in rule:
            return WAFType.MODSECURITY

        # Naxsi detection
        rule_lower = rule.lower()
        if (rule_lower.startswith('mainrule') or
            rule_lower.startswith('basicrule') or
            rule_lower.startswith('checkrule')):
            return WAFType.NAXSI

        # AWS WAF detection (JSON)
        if rule.startswith('{'):
            try:
                obj = json.loads(rule)
                aws_keys = {
                    'Statement', 'Rules', 'ByteMatchStatement',
                    'SqliMatchStatement', 'XssMatchStatement',
                    'FieldToMatch', 'TextTransformations',
                    'GeoMatchStatement', 'RateBasedStatement',
                }
                if any(k in str(obj) for k in aws_keys):
                    return WAFType.AWS_WAF
            except json.JSONDecodeError:
                pass

        # Cloudflare detection
        cf_indicators = ['http.', 'ip.src', 'cf.', 'ssl.', ' contains ', ' matches ']
        if any(ind in rule.lower() for ind in cf_indicators):
            return WAFType.CLOUDFLARE

        return None

    def validate_batch(
        self,
        rules: list[str],
        waf_type: Optional[WAFType] = None
    ) -> list[ValidationResult]:
        """
        Validate multiple rules.

        Args:
            rules: List of rule strings to validate
            waf_type: Optional WAF type. If None, auto-detect each rule.

        Returns:
            List of ValidationResult for each rule
        """
        return [self.validate(rule, waf_type) for rule in rules]

    def get_validator(self, waf_type: WAFType) -> Optional[BaseValidator]:
        """
        Get a specific validator instance.

        Args:
            waf_type: The WAF type

        Returns:
            The validator instance or None
        """
        return self.validators.get(waf_type)

    @property
    def supported_waf_types(self) -> list[WAFType]:
        """Return list of supported WAF types."""
        return list(self.validators.keys())


# Convenience function
def validate_rule(rule: str, waf_type: Optional[WAFType] = None) -> ValidationResult:
    """
    Validate a rule with optional WAF type specification.

    Args:
        rule: The rule string to validate
        waf_type: Optional WAF type. If None, auto-detect.

    Returns:
        ValidationResult
    """
    return SyntaxValidator().validate(rule, waf_type)
