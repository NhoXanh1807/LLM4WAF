"""
Naxsi WAF Rule Syntax Validator.

Validates Naxsi (Nginx Anti-XSS & SQL Injection) rule syntax offline.

Naxsi rule types:
- MainRule: Detection rules (http {} context)
- BasicRule: Whitelist rules (location {} context)
- CheckRule: Threshold/action rules
"""

import re
from typing import Optional

from .base import BaseValidator, ValidationResult, WAFType


class NaxsiValidator(BaseValidator):
    """
    Validate Naxsi WAF rule syntax offline.

    Naxsi uses a custom rule format for Nginx.

    Examples:
        MainRule "rx:select|union|update" "msg:sql keywords" "mz:BODY|URL|ARGS" "s:$SQL:4" id:1000;
        BasicRule wl:1000 "mz:$ARGS_VAR:query";
        CheckRule "$SQL >= 8" BLOCK;

    Usage:
        validator = NaxsiValidator()
        result = validator.validate('MainRule "rx:test" "msg:test" "mz:ARGS" "s:$XSS:4" id:1000;')
    """

    # Valid match zones
    VALID_MATCH_ZONES = {
        # Basic zones
        "ARGS", "HEADERS", "BODY", "URL", "FILE_EXT",
        # Named zones (with $ prefix)
        "$ARGS_VAR", "$HEADERS_VAR", "$BODY_VAR", "$URL",
        # Special zones
        "RAW_BODY", "NAME", "ANY",
    }

    # Valid score variables
    VALID_SCORE_VARS = {
        "$SQL", "$XSS", "$RFI", "$TRAVERSAL", "$EVADE", "$UPLOAD",
        "$ATTACK", "$UWA", "$DROP",
    }

    # Valid rule types
    VALID_RULE_TYPES = {
        "MainRule", "BasicRule", "CheckRule",
        "mainrule", "basicrule", "checkrule",  # case insensitive
    }

    # Valid operators for patterns
    VALID_OPERATORS = {
        "rx",      # Regex
        "str",     # String match
        "d",       # Libinjection detect
    }

    # Valid actions for CheckRule
    VALID_ACTIONS = {
        "BLOCK", "DROP", "ALLOW", "LOG", "LEARNING",
        "block", "drop", "allow", "log", "learning",
    }

    def get_waf_type(self) -> WAFType:
        return WAFType.NAXSI

    def validate(self, rule: str) -> ValidationResult:
        """Validate a Naxsi rule."""
        rule = rule.strip()

        if not rule:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message="Empty rule"
            )

        # Detect rule type
        rule_type = self._detect_rule_type(rule)

        if rule_type == "MainRule":
            return self._validate_main_rule(rule)
        elif rule_type == "BasicRule":
            return self._validate_basic_rule(rule)
        elif rule_type == "CheckRule":
            return self._validate_check_rule(rule)
        else:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message=f"Unknown rule type. Expected MainRule, BasicRule, or CheckRule"
            )

    def _detect_rule_type(self, rule: str) -> Optional[str]:
        """Detect the type of Naxsi rule."""
        rule_lower = rule.lower()
        if rule_lower.startswith("mainrule"):
            return "MainRule"
        elif rule_lower.startswith("basicrule"):
            return "BasicRule"
        elif rule_lower.startswith("checkrule"):
            return "CheckRule"
        return None

    def _validate_main_rule(self, rule: str) -> ValidationResult:
        """
        Validate MainRule syntax.

        Format: MainRule "rx/str/d:pattern" "msg:message" "mz:ZONES" "s:$VAR:score" id:N;
        """
        warnings = []

        # Check if rule ends with semicolon
        if not rule.rstrip().endswith(';'):
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message="MainRule must end with semicolon (;)"
            )

        # Extract components
        has_pattern = False
        has_msg = False
        has_mz = False
        has_score = False
        has_id = False
        rule_id = None

        # Pattern: "key:value" or key:value
        components = re.findall(r'"([^"]+)"|(\bid:\d+)', rule)

        for comp in components:
            quoted, id_match = comp

            if id_match:
                has_id = True
                rule_id = int(id_match.split(':')[1])
                continue

            if not quoted:
                continue

            # Check pattern (rx:, str:, d:)
            if quoted.startswith(('rx:', 'str:', 'd:')):
                has_pattern = True
                # Validate regex if rx:
                if quoted.startswith('rx:'):
                    pattern = quoted[3:]
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        return ValidationResult(
                            is_valid=False,
                            waf_type=WAFType.NAXSI,
                            error_message=f"Invalid regex pattern: {e}"
                        )

            # Check message
            elif quoted.startswith('msg:'):
                has_msg = True

            # Check match zone
            elif quoted.startswith('mz:'):
                has_mz = True
                mz_result = self._validate_match_zone(quoted[3:])
                if not mz_result.is_valid:
                    mz_result.waf_type = WAFType.NAXSI
                    return mz_result
                if mz_result.warnings:
                    warnings.extend(mz_result.warnings)

            # Check score
            elif quoted.startswith('s:'):
                has_score = True
                score_result = self._validate_score(quoted[2:])
                if not score_result.is_valid:
                    score_result.waf_type = WAFType.NAXSI
                    return score_result

        # Check required components
        if not has_pattern:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message="MainRule requires pattern (rx:, str:, or d:)"
            )

        if not has_msg:
            warnings.append("MainRule missing msg: (recommended)")

        if not has_mz:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message="MainRule requires match zone (mz:)"
            )

        if not has_score:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message="MainRule requires score (s:)"
            )

        if not has_id:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message="MainRule requires id:N"
            )

        return ValidationResult(
            is_valid=True,
            waf_type=WAFType.NAXSI,
            rule_id=rule_id,
            warnings=warnings if warnings else None,
            metadata={"rule_type": "MainRule"}
        )

    def _validate_basic_rule(self, rule: str) -> ValidationResult:
        """
        Validate BasicRule (whitelist) syntax.

        Format: BasicRule wl:ID[,ID...] "mz:ZONE[:name]";
        """
        warnings = []

        # Check if rule ends with semicolon
        if not rule.rstrip().endswith(';'):
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message="BasicRule must end with semicolon (;)"
            )

        # Check for wl: (whitelist)
        wl_match = re.search(r'\bwl:(\d+(?:,\d+)*)', rule)
        if not wl_match:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message="BasicRule requires wl:ID (whitelist rule IDs)"
            )

        # Extract whitelisted IDs
        wl_ids = wl_match.group(1).split(',')

        # Check for match zone
        mz_match = re.search(r'"mz:([^"]+)"', rule)
        if not mz_match:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message="BasicRule requires match zone (mz:)"
            )

        mz_result = self._validate_match_zone(mz_match.group(1))
        if not mz_result.is_valid:
            mz_result.waf_type = WAFType.NAXSI
            return mz_result
        if mz_result.warnings:
            warnings.extend(mz_result.warnings)

        return ValidationResult(
            is_valid=True,
            waf_type=WAFType.NAXSI,
            warnings=warnings if warnings else None,
            metadata={
                "rule_type": "BasicRule",
                "whitelist_ids": [int(i) for i in wl_ids]
            }
        )

    def _validate_check_rule(self, rule: str) -> ValidationResult:
        """
        Validate CheckRule syntax.

        Format: CheckRule "$VAR >= N" ACTION;
        """
        # Check if rule ends with semicolon
        if not rule.rstrip().endswith(';'):
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message="CheckRule must end with semicolon (;)"
            )

        # Pattern: CheckRule "condition" ACTION;
        pattern = r'CheckRule\s+"([^"]+)"\s+(\w+)\s*;'
        match = re.match(pattern, rule, re.IGNORECASE)

        if not match:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message='Invalid CheckRule syntax. Expected: CheckRule "$VAR >= N" ACTION;'
            )

        condition = match.group(1)
        action = match.group(2)

        # Validate condition
        cond_pattern = r'(\$\w+)\s*(>=|>|<=|<|==|!=)\s*(\d+)'
        cond_match = re.match(cond_pattern, condition)

        if not cond_match:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message=f'Invalid condition: "{condition}". Expected: $VAR >= N'
            )

        var_name = cond_match.group(1)
        if var_name not in self.VALID_SCORE_VARS:
            # Allow custom score variables but warn
            pass

        # Validate action
        if action.upper() not in [a.upper() for a in self.VALID_ACTIONS]:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.NAXSI,
                error_message=f"Invalid action: {action}. Valid actions: {', '.join(sorted(set(a.upper() for a in self.VALID_ACTIONS)))}"
            )

        return ValidationResult(
            is_valid=True,
            waf_type=WAFType.NAXSI,
            metadata={
                "rule_type": "CheckRule",
                "condition": condition,
                "action": action.upper()
            }
        )

    def _validate_match_zone(self, mz: str) -> ValidationResult:
        """Validate match zone specification."""
        warnings = []

        # Split by | for multiple zones
        zones = mz.split('|')

        for zone in zones:
            zone = zone.strip()

            # Handle zone with variable name (e.g., $ARGS_VAR:param_name)
            if ':' in zone:
                base_zone, var_name = zone.split(':', 1)
            else:
                base_zone = zone
                var_name = None

            # Check base zone
            base_zone_upper = base_zone.upper()
            if base_zone_upper not in self.VALID_MATCH_ZONES:
                # Check with $ prefix
                if base_zone.startswith('$'):
                    base_check = base_zone.upper()
                else:
                    base_check = f"${base_zone_upper}"

                if base_check not in self.VALID_MATCH_ZONES and base_zone_upper not in self.VALID_MATCH_ZONES:
                    warnings.append(f"Unknown match zone: {base_zone}")

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_score(self, score: str) -> ValidationResult:
        """Validate score specification."""
        # Format: $VAR:N or $VAR:+N
        parts = score.split(':')

        if len(parts) != 2:
            return ValidationResult(
                is_valid=False,
                error_message=f"Invalid score format: {score}. Expected: $VAR:N"
            )

        var_name, value = parts

        # Check variable name
        if not var_name.startswith('$'):
            var_name = f"${var_name}"

        if var_name.upper() not in self.VALID_SCORE_VARS:
            # Allow but it's unusual
            pass

        # Check value is numeric (can have + prefix)
        value = value.lstrip('+')
        if not value.lstrip('-').isdigit():
            return ValidationResult(
                is_valid=False,
                error_message=f"Invalid score value: {value}. Must be numeric"
            )

        return ValidationResult(is_valid=True)


def validate_naxsi_rule(rule: str) -> ValidationResult:
    """
    Convenience function to validate a Naxsi rule.

    Args:
        rule: Naxsi rule string

    Returns:
        ValidationResult
    """
    return NaxsiValidator().validate(rule)
