"""
AWS WAF Rule Syntax Validator.

Validates AWS WAF rule JSON syntax offline.

Leniency policy (2026):
  Hard-fail: invalid JSON, completely missing statement type.
  Warning:   unknown statement types, missing optional fields (Priority, VisibilityConfig).
  Pass:      everything else — AWS WAF v2 / WAFV2 is flexible.
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
        # 2026 additions
        "AsnMatchStatement",
        "HeaderMatchStatement",
        "CookieMatchStatement",
    }

    VALID_FIELD_TO_MATCH = {
        "SingleHeader", "SingleQueryArgument", "AllQueryArguments",
        "UriPath", "QueryString", "Body", "JsonBody",
        "Method", "Headers", "Cookies", "HeaderOrder",
        "JA3Fingerprint",
        # 2026 additions
        "JA4Fingerprint", "Asn", "UriFragment",
    }

    VALID_TEXT_TRANSFORMATIONS = {
        "NONE", "COMPRESS_WHITE_SPACE", "HTML_ENTITY_DECODE",
        "LOWERCASE", "CMD_LINE", "URL_DECODE", "BASE64_DECODE",
        "HEX_DECODE", "MD5", "REPLACE_COMMENTS", "ESCAPE_SEQ_DECODE",
        "SQL_HEX_DECODE", "CSS_DECODE", "JS_DECODE",
        "NORMALIZE_PATH", "NORMALIZE_PATH_WIN", "REMOVE_NULLS",
        "REPLACE_NULLS", "BASE64_DECODE_EXT", "URL_DECODE_UNI",
        "UTF8_TO_UNICODE",
    }

    VALID_COMPARISON_OPERATORS = {"EQ", "NE", "LE", "LT", "GE", "GT"}
    VALID_POSITIONAL_CONSTRAINTS = {"EXACTLY", "STARTS_WITH", "ENDS_WITH", "CONTAINS", "CONTAINS_WORD"}
    VALID_ACTIONS = {"Allow", "Block", "Count", "Captcha", "Challenge"}

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

        # Hard-fail: must be valid JSON
        try:
            rule_obj = json.loads(rule)
        except json.JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.AWS_WAF,
                error_message=f"Invalid JSON: {str(e)}"
            )

        warnings = []

        result = self._validate_rule_structure(rule_obj)
        if not result.is_valid:
            result.waf_type = WAFType.AWS_WAF
            return result
        if result.warnings:
            warnings.extend(result.warnings)

        rule_id = rule_obj.get("Name") or rule_obj.get("RuleId")

        return ValidationResult(
            is_valid=True,
            waf_type=WAFType.AWS_WAF,
            rule_id=rule_id,
            warnings=warnings if warnings else None,
            metadata={"rule_type": self._detect_rule_type(rule_obj)}
        )

    def _validate_rule_structure(self, rule: dict) -> ValidationResult:
        warnings = []

        if "Statement" in rule:
            result = self._validate_statement(rule["Statement"])
            if not result.is_valid:
                return result
            if result.warnings:
                warnings.extend(result.warnings)

            if "Action" in rule:
                action_result = self._validate_action(rule["Action"])
                if not action_result.is_valid:
                    return action_result

            # VisibilityConfig is optional — warn if missing, don't fail
            if "VisibilityConfig" not in rule:
                warnings.append("VisibilityConfig missing (required for AWS console but optional for API)")

        elif "Rules" in rule:
            for i, r in enumerate(rule.get("Rules", [])):
                result = self._validate_rule_structure(r)
                if not result.is_valid:
                    result.error_message = f"Rule[{i}]: {result.error_message}"
                    return result
                if result.warnings:
                    warnings.extend([f"Rule[{i}]: {w}" for w in result.warnings])

        elif any(st in rule for st in self.VALID_STATEMENT_TYPES):
            result = self._validate_statement(rule)
            if not result.is_valid:
                return result
            if result.warnings:
                warnings.extend(result.warnings)

        else:
            # Try to treat the whole object as a statement
            result = self._validate_statement(rule)
            if not result.is_valid:
                # Downgrade to warning — may be a partial rule or wrapper
                warnings.append(f"Could not identify statement type: {list(rule.keys())[:5]}")

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_statement(self, statement: dict) -> ValidationResult:
        if not statement:
            return ValidationResult(is_valid=False, error_message="Empty statement")

        warnings = []

        statement_type = None
        for st in self.VALID_STATEMENT_TYPES:
            if st in statement:
                statement_type = st
                break

        if not statement_type:
            # Check for unknown *Statement keys — warn, don't fail
            for key in statement.keys():
                if key.endswith("Statement"):
                    warnings.append(f"Unknown statement type: {key} (may be a 2026 AWS WAF feature)")
                    return ValidationResult(is_valid=True, warnings=warnings)
            # No statement key at all — might be a nested object
            return ValidationResult(is_valid=True, warnings=["No recognised statement key found"])

        stmt_content = statement[statement_type]

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
                return ValidationResult(is_valid=False, error_message="NotStatement requires inner Statement")
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
            # These are valid with just a FieldToMatch — very lenient
            pass

        elif statement_type == "SizeConstraintStatement":
            result = self._validate_size_statement(stmt_content)
            if not result.is_valid:
                return result

        elif statement_type == "GeoMatchStatement":
            result = self._validate_geo_statement(stmt_content)
            if not result.is_valid:
                return result

        # Other statement types: pass without deep validation

        if "FieldToMatch" in stmt_content:
            result = self._validate_field_to_match(stmt_content["FieldToMatch"])
            if not result.is_valid:
                return result

        if "TextTransformations" in stmt_content:
            result = self._validate_text_transformations(stmt_content["TextTransformations"])
            if not result.is_valid:
                return result
            if result.warnings:
                warnings.extend(result.warnings)

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_match_statement(self, content: dict, stmt_type: str) -> ValidationResult:
        warnings = []

        if stmt_type == "ByteMatchStatement":
            if "SearchString" not in content:
                return ValidationResult(is_valid=False, error_message="ByteMatchStatement requires SearchString")
            if "PositionalConstraint" in content:
                pc = content["PositionalConstraint"]
                if pc not in self.VALID_POSITIONAL_CONSTRAINTS:
                    warnings.append(f"Unrecognised PositionalConstraint: {pc}")

        elif stmt_type == "RegexMatchStatement":
            if "RegexString" not in content:
                return ValidationResult(is_valid=False, error_message="RegexMatchStatement requires RegexString")
            try:
                re.compile(content["RegexString"])
            except re.error as e:
                return ValidationResult(is_valid=False, error_message=f"Invalid regex: {e}")

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_size_statement(self, content: dict) -> ValidationResult:
        warnings = []
        if "ComparisonOperator" in content:
            op = content["ComparisonOperator"]
            if op not in self.VALID_COMPARISON_OPERATORS:
                warnings.append(f"Unrecognised ComparisonOperator: {op}")
        else:
            warnings.append("SizeConstraintStatement missing ComparisonOperator")
        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_geo_statement(self, content: dict) -> ValidationResult:
        if "CountryCodes" not in content:
            return ValidationResult(is_valid=False, error_message="GeoMatchStatement requires CountryCodes")
        codes = content["CountryCodes"]
        if not isinstance(codes, list) or not codes:
            return ValidationResult(is_valid=False, error_message="CountryCodes must be a non-empty array")
        return ValidationResult(is_valid=True)

    def _validate_field_to_match(self, field: dict) -> ValidationResult:
        if not field:
            return ValidationResult(is_valid=True)
        unknown = [k for k in field.keys() if k not in self.VALID_FIELD_TO_MATCH]
        if unknown and not any(k in field for k in self.VALID_FIELD_TO_MATCH):
            return ValidationResult(
                is_valid=True,
                warnings=[f"Unknown FieldToMatch type(s): {unknown} (may be newer AWS WAF feature)"]
            )
        return ValidationResult(is_valid=True)

    def _validate_text_transformations(self, transformations: list) -> ValidationResult:
        """Validate TextTransformations — Priority is now a warning, not hard-fail."""
        if not isinstance(transformations, list):
            return ValidationResult(is_valid=False, error_message="TextTransformations must be an array")

        warnings = []
        for i, t in enumerate(transformations):
            if not isinstance(t, dict):
                return ValidationResult(is_valid=False, error_message=f"TextTransformation[{i}] must be an object")

            if "Priority" not in t:
                warnings.append(f"TextTransformation[{i}] missing Priority (defaults to 0)")

            if "Type" not in t:
                warnings.append(f"TextTransformation[{i}] missing Type")
            elif t["Type"] not in self.VALID_TEXT_TRANSFORMATIONS:
                warnings.append(f"Unknown TextTransformation Type: {t['Type']} (may be newer AWS WAF feature)")

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_action(self, action: dict) -> ValidationResult:
        if not any(a in action for a in self.VALID_ACTIONS):
            return ValidationResult(
                is_valid=True,
                warnings=[f"Unrecognised action keys: {list(action.keys())} — expected one of {sorted(self.VALID_ACTIONS)}"]
            )
        return ValidationResult(is_valid=True)

    def _detect_rule_type(self, rule: dict) -> str:
        if "Rules" in rule:
            return "WebACL/RuleGroup"
        if "Statement" in rule:
            return "Rule"
        for st in self.VALID_STATEMENT_TYPES:
            if st in rule:
                return st
        return "Unknown"


def validate_aws_waf_rule(rule: str) -> ValidationResult:
    return AWSWAFValidator().validate(rule)
