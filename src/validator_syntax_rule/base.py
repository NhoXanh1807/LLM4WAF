

"""
Base classes for WAF rule syntax validators.

This module provides the foundation for all WAF-specific validators.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Union
from enum import Enum


class WAFType(Enum):
    """Supported WAF types."""
    MODSECURITY = "modsecurity"
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    NAXSI = "naxsi"


@dataclass
class ValidationResult:
    """
    Result of syntax validation.

    Attributes:
        is_valid: Whether the rule syntax is valid
        waf_type: The WAF type that was validated
        error_message: Error description if validation failed
        rule_id: Extracted rule ID (if any)
        warnings: List of non-fatal warnings
        metadata: Additional metadata about the rule
    """
    is_valid: bool
    waf_type: Optional[WAFType] = None
    error_message: Optional[str] = None
    rule_id: Optional[Union[int, str]] = None
    warnings: Optional[list[str]] = None
    metadata: dict = field(default_factory=dict)

    def __str__(self) -> str:
        if self.is_valid:
            return f"Valid ({self.waf_type.value if self.waf_type else 'unknown'})"
        return f"Invalid: {self.error_message}"

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "is_valid": self.is_valid,
            "waf_type": self.waf_type.value if self.waf_type else None,
            "error_message": self.error_message,
            "rule_id": self.rule_id,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


class BaseValidator(ABC):
    """
    Abstract base class for WAF validators.

    All WAF-specific validators must inherit from this class
    and implement the required methods.
    """

    @abstractmethod
    def validate(self, rule: str) -> ValidationResult:
        """
        Validate a rule and return result.

        Args:
            rule: The rule string to validate

        Returns:
            ValidationResult with validation status and details
        """
        pass

    @abstractmethod
    def get_waf_type(self) -> WAFType:
        """
        Return the WAF type this validator handles.

        Returns:
            WAFType enum value
        """
        pass

    def validate_batch(self, rules: list[str]) -> list[ValidationResult]:
        """
        Validate multiple rules.

        Args:
            rules: List of rule strings to validate

        Returns:
            List of ValidationResult for each rule
        """
        return [self.validate(rule) for rule in rules]
