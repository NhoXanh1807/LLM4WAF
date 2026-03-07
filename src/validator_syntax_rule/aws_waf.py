"""
AWS WAF Rule Syntax Validator.

Validates AWS WAF rule JSON syntax offline.
"""

import json
import re
from typing import Optional

from .base import BaseValidator, ValidationResult, WAFType


class AWSWAFValidator(BaseValidator):
    """
    Validate AWS WAF rule JSON syntax offline.

    AWS WAF rules are defined in JSON format with specific statement types.

    Usage:
        validator = AWSWAFValidator()
        result = validator.validate(json_rule_string)
    """

    # Valid statement types
    VALID_STATEMENT_TYPES = {
        "ByteMatchStatement",
        "SqliMatchStatement",
        "XssMatchStatement",
        "SizeConstraintStatement",
        "GeoMatchStatement",
        "RuleGroupReferenceStatement",
        "IPSetReferenceStatement",
        "RegexPatternSetReferenceStatement",
        "RegexMatchStatement",
        "RateBasedStatement",
        "AndStatement",
        "OrStatement",
        "NotStatement",
        "ManagedRuleGroupStatement",
        "LabelMatchStatement",
    }

    # Valid field to match
    VALID_FIELD_TO_MATCH = {
        "SingleHeader", "SingleQueryArgument", "AllQueryArguments",
        "UriPath", "QueryString", "Body", "JsonBody",
        "Method", "Headers", "Cookies", "HeaderOrder",
        "JA3Fingerprint",
    }

    # Valid text transformations
    VALID_TEXT_TRANSFORMATIONS = {
        "NONE", "COMPRESS_WHITE_SPACE", "HTML_ENTITY_DECODE",
        "LOWERCASE", "CMD_LINE", "URL_DECODE", "BASE64_DECODE",
        "HEX_DECODE", "MD5", "REPLACE_COMMENTS", "ESCAPE_SEQ_DECODE",
        "SQL_HEX_DECODE", "CSS_DECODE", "JS_DECODE",
        "NORMALIZE_PATH", "NORMALIZE_PATH_WIN", "REMOVE_NULLS",
        "REPLACE_NULLS", "BASE64_DECODE_EXT", "URL_DECODE_UNI",
        "UTF8_TO_UNICODE",
    }

    # Valid comparison operators
    VALID_COMPARISON_OPERATORS = {
        "EQ", "NE", "LE", "LT", "GE", "GT",
    }

    # Valid positional constraints
    VALID_POSITIONAL_CONSTRAINTS = {
        "EXACTLY", "STARTS_WITH", "ENDS_WITH", "CONTAINS", "CONTAINS_WORD",
    }

    # Valid actions
    VALID_ACTIONS = {
        "Allow", "Block", "Count", "Captcha", "Challenge",
    }

    def get_waf_type(self) -> WAFType:
        return WAFType.AWS_WAF

    def validate(self, rule: str) -> ValidationResult:
        """Validate an AWS WAF rule (JSON format)."""
        rule = rule.strip()

        if not rule:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.AWS_WAF,
                error_message="Empty rule"
            )

        # Try to parse as JSON
        try:
            rule_obj = json.loads(rule)
        except json.JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.AWS_WAF,
                error_message=f"Invalid JSON: {str(e)}"
            )

        warnings = []

        # Validate the rule structure
        result = self._validate_rule_structure(rule_obj)
        if not result.is_valid:
            result.waf_type = WAFType.AWS_WAF
            return result
        if result.warnings:
            warnings.extend(result.warnings)

        # Extract rule name/ID
        rule_id = rule_obj.get("Name") or rule_obj.get("RuleId")

        return ValidationResult(
            is_valid=True,
            waf_type=WAFType.AWS_WAF,
            rule_id=rule_id,
            warnings=warnings if warnings else None,
            metadata={"rule_type": self._detect_rule_type(rule_obj)}
        )

    def _validate_rule_structure(self, rule: dict) -> ValidationResult:
        """Validate the overall rule structure."""
        warnings = []

        if "Statement" in rule:
            result = self._validate_statement(rule.get("Statement", {}))
            if not result.is_valid:
                return result
            if result.warnings:
                warnings.extend(result.warnings)

            if "Action" in rule:
                action_result = self._validate_action(rule["Action"])
                if not action_result.is_valid:
                    return action_result

            if "VisibilityConfig" in rule:
                vis_result = self._validate_visibility_config(rule["VisibilityConfig"])
                if not vis_result.is_valid:
                    return vis_result

        elif "Rules" in rule:
            for i, r in enumerate(rule.get("Rules", [])):
                result = self._validate_rule_structure(r)
                if not result.is_valid:
                    result.error_message = f"Rule {i}: {result.error_message}"
                    return result
                if result.warnings:
                    warnings.extend([f"Rule {i}: {w}" for w in result.warnings])

        elif any(st in rule for st in self.VALID_STATEMENT_TYPES):
            result = self._validate_statement(rule)
            if not result.is_valid:
                return result
            if result.warnings:
                warnings.extend(result.warnings)

        else:
            result = self._validate_statement(rule)
            if not result.is_valid:
                return result

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_statement(self, statement: dict) -> ValidationResult:
        """Validate a single statement."""
        if not statement:
            return ValidationResult(
                is_valid=False,
                error_message="Empty statement"
            )

        warnings = []

        # Find the statement type
        statement_type = None
        for st in self.VALID_STATEMENT_TYPES:
            if st in statement:
                statement_type = st
                break

        if not statement_type:
            for key in statement.keys():
                if key.endswith("Statement"):
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Unknown statement type: {key}"
                    )
            return ValidationResult(
                is_valid=False,
                error_message="No valid statement type found"
            )

        stmt_content = statement[statement_type]

        # Validate based on statement type
        if statement_type in {"AndStatement", "OrStatement"}:
            statements = stmt_content.get("Statements", [])
            if not statements:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"{statement_type} requires non-empty Statements array"
                )
            for i, s in enumerate(statements):
                result = self._validate_statement(s)
                if not result.is_valid:
                    result.error_message = f"{statement_type}[{i}]: {result.error_message}"
                    return result

        elif statement_type == "NotStatement":
            inner = stmt_content.get("Statement")
            if not inner:
                return ValidationResult(
                    is_valid=False,
                    error_message="NotStatement requires inner Statement"
                )
            result = self._validate_statement(inner)
            if not result.is_valid:
                return result

        elif statement_type in {"ByteMatchStatement", "RegexMatchStatement"}:
            result = self._validate_match_statement(stmt_content, statement_type)
            if not result.is_valid:
                return result
            if result.warnings:
                warnings.extend(result.warnings)

        elif statement_type in {"SqliMatchStatement", "XssMatchStatement"}:
            result = self._validate_injection_statement(stmt_content)
            if not result.is_valid:
                return result

        elif statement_type == "SizeConstraintStatement":
            result = self._validate_size_statement(stmt_content)
            if not result.is_valid:
                return result

        elif statement_type == "GeoMatchStatement":
            result = self._validate_geo_statement(stmt_content)
            if not result.is_valid:
                return result

        elif statement_type == "IPSetReferenceStatement":
            if "ARN" not in stmt_content:
                return ValidationResult(
                    is_valid=False,
                    error_message="IPSetReferenceStatement requires ARN"
                )

        elif statement_type == "RegexPatternSetReferenceStatement":
            if "ARN" not in stmt_content:
                return ValidationResult(
                    is_valid=False,
                    error_message="RegexPatternSetReferenceStatement requires ARN"
                )
            result = self._validate_field_to_match(stmt_content.get("FieldToMatch", {}))
            if not result.is_valid:
                return result

        elif statement_type == "RateBasedStatement":
            result = self._validate_rate_statement(stmt_content)
            if not result.is_valid:
                return result

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_match_statement(self, content: dict, stmt_type: str) -> ValidationResult:
        """Validate ByteMatchStatement or RegexMatchStatement."""
        warnings = []

        if stmt_type == "ByteMatchStatement":
            if "SearchString" not in content:
                return ValidationResult(
                    is_valid=False,
                    error_message="ByteMatchStatement requires SearchString"
                )
            if "PositionalConstraint" in content:
                pc = content["PositionalConstraint"]
                if pc not in self.VALID_POSITIONAL_CONSTRAINTS:
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Invalid PositionalConstraint: {pc}"
                    )

        elif stmt_type == "RegexMatchStatement":
            if "RegexString" not in content:
                return ValidationResult(
                    is_valid=False,
                    error_message="RegexMatchStatement requires RegexString"
                )
            try:
                re.compile(content["RegexString"])
            except re.error as e:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Invalid regex pattern: {str(e)}"
                )

        if "FieldToMatch" in content:
            result = self._validate_field_to_match(content["FieldToMatch"])
            if not result.is_valid:
                return result

        if "TextTransformations" in content:
            result = self._validate_text_transformations(content["TextTransformations"])
            if not result.is_valid:
                return result

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_injection_statement(self, content: dict) -> ValidationResult:
        """Validate SqliMatchStatement or XssMatchStatement."""
        if "FieldToMatch" in content:
            result = self._validate_field_to_match(content["FieldToMatch"])
            if not result.is_valid:
                return result

        if "TextTransformations" in content:
            result = self._validate_text_transformations(content["TextTransformations"])
            if not result.is_valid:
                return result

        return ValidationResult(is_valid=True)

    def _validate_size_statement(self, content: dict) -> ValidationResult:
        """Validate SizeConstraintStatement."""
        if "ComparisonOperator" not in content:
            return ValidationResult(
                is_valid=False,
                error_message="SizeConstraintStatement requires ComparisonOperator"
            )

        op = content["ComparisonOperator"]
        if op not in self.VALID_COMPARISON_OPERATORS:
            return ValidationResult(
                is_valid=False,
                error_message=f"Invalid ComparisonOperator: {op}"
            )

        if "Size" not in content:
            return ValidationResult(
                is_valid=False,
                error_message="SizeConstraintStatement requires Size"
            )

        if "FieldToMatch" in content:
            result = self._validate_field_to_match(content["FieldToMatch"])
            if not result.is_valid:
                return result

        return ValidationResult(is_valid=True)

    def _validate_geo_statement(self, content: dict) -> ValidationResult:
        """Validate GeoMatchStatement."""
        if "CountryCodes" not in content:
            return ValidationResult(
                is_valid=False,
                error_message="GeoMatchStatement requires CountryCodes"
            )

        codes = content["CountryCodes"]
        if not isinstance(codes, list) or not codes:
            return ValidationResult(
                is_valid=False,
                error_message="CountryCodes must be a non-empty array"
            )

        for code in codes:
            if not isinstance(code, str) or len(code) != 2:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Invalid country code: {code}"
                )

        return ValidationResult(is_valid=True)

    def _validate_rate_statement(self, content: dict) -> ValidationResult:
        """Validate RateBasedStatement."""
        if "Limit" not in content:
            return ValidationResult(
                is_valid=False,
                error_message="RateBasedStatement requires Limit"
            )

        limit = content["Limit"]
        if not isinstance(limit, int) or limit < 100:
            return ValidationResult(
                is_valid=False,
                error_message="Limit must be an integer >= 100"
            )

        if "AggregateKeyType" not in content:
            return ValidationResult(
                is_valid=False,
                error_message="RateBasedStatement requires AggregateKeyType"
            )

        return ValidationResult(is_valid=True)

    def _validate_field_to_match(self, field: dict) -> ValidationResult:
        """Validate FieldToMatch structure."""
        if not field:
            return ValidationResult(is_valid=True)

        valid_field_found = False
        for f in self.VALID_FIELD_TO_MATCH:
            if f in field:
                valid_field_found = True
                break

        if not valid_field_found and field:
            unknown_fields = [k for k in field.keys() if k not in self.VALID_FIELD_TO_MATCH]
            if unknown_fields:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Unknown FieldToMatch type: {unknown_fields[0]}"
                )

        return ValidationResult(is_valid=True)

    def _validate_text_transformations(self, transformations: list) -> ValidationResult:
        """Validate TextTransformations array."""
        if not isinstance(transformations, list):
            return ValidationResult(
                is_valid=False,
                error_message="TextTransformations must be an array"
            )

        for i, t in enumerate(transformations):
            if not isinstance(t, dict):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"TextTransformation[{i}] must be an object"
                )

            if "Priority" not in t:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"TextTransformation[{i}] requires Priority"
                )

            if "Type" not in t:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"TextTransformation[{i}] requires Type"
                )

            if t["Type"] not in self.VALID_TEXT_TRANSFORMATIONS:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Invalid TextTransformation Type: {t['Type']}"
                )

        return ValidationResult(is_valid=True)

    def _validate_action(self, action: dict) -> ValidationResult:
        """Validate rule action."""
        valid_action_found = False
        for a in self.VALID_ACTIONS:
            if a in action:
                valid_action_found = True
                break

        if not valid_action_found:
            return ValidationResult(
                is_valid=False,
                error_message=f"Invalid action. Must be one of: {', '.join(self.VALID_ACTIONS)}"
            )

        return ValidationResult(is_valid=True)

    def _validate_visibility_config(self, config: dict) -> ValidationResult:
        """Validate VisibilityConfig."""
        required_fields = ["SampledRequestsEnabled", "CloudWatchMetricsEnabled", "MetricName"]
        for field in required_fields:
            if field not in config:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"VisibilityConfig requires {field}"
                )
        return ValidationResult(is_valid=True)

    def _detect_rule_type(self, rule: dict) -> str:
        """Detect the type of AWS WAF rule."""
        if "Rules" in rule:
            return "WebACL/RuleGroup"
        if "Statement" in rule:
            return "Rule"
        for st in self.VALID_STATEMENT_TYPES:
            if st in rule:
                return st
        return "Unknown"


def validate_aws_waf_rule(rule: str) -> ValidationResult:
    """
    Convenience function to validate an AWS WAF rule.

    Args:
        rule: AWS WAF rule JSON string

    Returns:
        ValidationResult
    """
    return AWSWAFValidator().validate(rule)
