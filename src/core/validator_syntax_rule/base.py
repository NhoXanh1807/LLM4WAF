

"""
Base classes for WAF rule syntax validators.

This module provides the foundation for all WAF-specific validators.
"""

from abc import ABC, abstractmethod
from ..dtos import ValidationResult, WAFType


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
