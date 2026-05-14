

"""
Base classes for WAF rule syntax validators.

This module provides the foundation for all WAF-specific validators.
"""

from abc import ABC, abstractmethod
from models.dtos import ValidationResult, WAFType


class BaseValidator(ABC):
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

