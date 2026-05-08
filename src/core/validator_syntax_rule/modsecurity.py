"""
ModSecurity Rule Syntax Validator.

Validates ModSecurity SecRule syntax offline.
Supports both pymodsecurity (libmodsecurity) and pure Python fallback.

Leniency policy (2026):
  Hard-fail: completely unparseable structure, or missing required `id` action.
  Warning:   unknown variables, operators, actions, transformations.
  Pass:      everything else — benefit of the doubt to LLM-generated rules.
"""

import re
from typing import Optional

from .base import BaseValidator, ValidationResult, WAFType


class ModSecurityValidator(BaseValidator):
    """
    Validate ModSecurity SecRule syntax offline.

    Supports two backends:
    1. pymodsecurity (requires libmodsecurity) - most accurate
    2. Pure Python regex parser - fallback, lenient mode

    Usage:
        validator = ModSecurityValidator()
        result = validator.validate('SecRule ARGS "@rx <script>" "id:1,deny"')
    """

    # Known variables — extended for 2026 CRS / ModSecurity 3.x
    KNOWN_VARIABLES = {
        "ARGS", "ARGS_GET", "ARGS_POST", "ARGS_NAMES", "ARGS_GET_NAMES", "ARGS_POST_NAMES",
        "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME", "REQUEST_BASENAME",
        "REQUEST_LINE", "REQUEST_METHOD", "REQUEST_PROTOCOL", "REQUEST_BODY",
        "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES", "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES",
        "QUERY_STRING", "AUTH_TYPE", "FULL_REQUEST", "FULL_REQUEST_LENGTH",
        "FILES", "FILES_NAMES", "FILES_SIZES", "FILES_COMBINED_SIZE", "FILES_TMPNAMES",
        "MULTIPART_STRICT_ERROR", "MULTIPART_UNMATCHED_BOUNDARY",
        "MULTIPART_CRLF_LF_LINES", "MULTIPART_INVALID_QUOTING",
        "RESPONSE_BODY", "RESPONSE_CONTENT_LENGTH", "RESPONSE_CONTENT_TYPE",
        "RESPONSE_HEADERS", "RESPONSE_HEADERS_NAMES", "RESPONSE_PROTOCOL",
        "RESPONSE_STATUS",
        "REMOTE_ADDR", "REMOTE_HOST", "REMOTE_PORT", "REMOTE_USER",
        "SERVER_ADDR", "SERVER_NAME", "SERVER_PORT",
        "TX", "IP", "GEO", "SESSION", "USER",
        "MATCHED_VAR", "MATCHED_VAR_NAME", "MATCHED_VARS", "MATCHED_VARS_NAMES",
        "RULE", "ENV", "DURATION", "TIME", "TIME_DAY", "TIME_EPOCH",
        "TIME_HOUR", "TIME_MIN", "TIME_MON", "TIME_SEC", "TIME_WDAY", "TIME_YEAR",
        "UNIQUE_ID", "URLENCODED_ERROR", "WEBSERVER_ERROR_LOG",
        "XML", "REQBODY_ERROR", "REQBODY_ERROR_MSG", "REQBODY_PROCESSOR",
        "GLOBAL", "RESOURCE", "PERF_RULES", "PERF_SREAD", "PERF_SWRITE",
        "PERF_GC", "PERF_LOGGING", "PERF_PHASE1", "PERF_PHASE2",
        "PERF_PHASE3", "PERF_PHASE4", "PERF_PHASE5", "PERF_COMBINED",
        "REQUEST_BODY_ERROR", "REQUEST_BODY_ERROR_MSG",
        "INBOUND_ERROR_DATA", "OUTBOUND_ERROR_DATA",
    }

    # Known operators — ModSecurity 3.x / Coraza 2026
    KNOWN_OPERATORS = {
        "@rx", "@pm", "@pmf", "@pmFromFile",
        "@streq", "@strmatch", "@contains", "@containsWord",
        "@beginsWith", "@endsWith", "@within",
        "@eq", "@ge", "@gt", "@le", "@lt",
        "@ipMatch", "@ipMatchF", "@ipMatchFromFile",
        "@geoLookup", "@rbl",
        "@validateByteRange", "@validateDTD", "@validateHash",
        "@validateSchema", "@validateUrlEncoding", "@validateUtf8Encoding",
        "@verifyCC", "@verifyCPF", "@verifySSN",
        "@detectSQLi", "@detectXSS",
        "@inspectFile", "@fuzzyHash",
        "@unconditionalMatch", "@noMatch",
        "@rsub", "@gsub",
    }

    KNOWN_ACTIONS = {
        "block", "deny", "drop", "allow", "pass", "pause", "proxy", "redirect",
        "capture", "chain", "ctl", "exec", "expirevar", "id", "initcol",
        "log", "logdata", "msg", "multiMatch", "nolog", "noauditlog", "auditlog",
        "phase", "prepend", "append", "sanitiseArg", "sanitiseMatched",
        "sanitiseMatchedBytes", "sanitiseRequestHeader", "sanitiseResponseHeader",
        "setuid", "setrsc", "setsid", "setenv", "setvar", "severity", "skip",
        "skipAfter", "status", "tag", "ver", "xmlns", "t", "rev", "maturity",
        "accuracy", "transformation", "xmlns", "nolog",
    }

    KNOWN_TRANSFORMATIONS = {
        "none", "lowercase", "uppercase", "urlDecode", "urlDecodeUni",
        "urlEncode", "htmlEntityDecode", "base64Decode", "base64DecodeExt",
        "base64Encode", "hexDecode", "hexEncode", "jsDecode", "cssDecode",
        "cmdLine", "compressWhitespace", "length", "md5", "sha1",
        "normalisePath", "normalisePathWin", "normalizePath", "normalizePathWin",
        "parityEven7bit", "parityOdd7bit", "parityZero7bit",
        "removeNulls", "removeWhitespace", "removeComments", "removeCommentsChar",
        "replaceComments", "replaceNulls", "sqlHexDecode", "trimLeft", "trimRight",
        "trim", "utf8toUnicode", "escapeSeqDecode",
    }

    def __init__(self, use_libmodsecurity: bool = True):
        self.libmodsec_available = False
        self._modsec = None
        self._Rules = None

        if use_libmodsecurity:
            try:
                from ModSecurity import ModSecurity, Rules
                self._modsec = ModSecurity()
                self._Rules = Rules
                self.libmodsec_available = True
            except ImportError:
                pass

    def get_waf_type(self) -> WAFType:
        return WAFType.MODSECURITY

    def validate(self, rule: str) -> ValidationResult:
        """Validate a ModSecurity rule."""
        rule = rule.strip()

        if not rule:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.MODSECURITY,
                error_message="Empty rule"
            )

        if self.libmodsec_available:
            return self._validate_with_libmodsecurity(rule)

        return self._validate_with_python(rule)

    def _validate_with_libmodsecurity(self, rule: str) -> ValidationResult:
        rules = self._Rules()
        rules.load(rule)
        error = rules.getParserError()

        if error:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.MODSECURITY,
                error_message=error
            )

        return ValidationResult(
            is_valid=True,
            waf_type=WAFType.MODSECURITY,
            rule_id=self._extract_rule_id(rule)
        )

    def _validate_with_python(self, rule: str) -> ValidationResult:
        """Validate using pure Python — lenient mode."""
        warnings = []
        lines = self._normalize_rule(rule)

        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.startswith('SecRule'):
                result = self._validate_secrule(line)
                if not result.is_valid:
                    result.waf_type = WAFType.MODSECURITY
                    return result
                if result.warnings:
                    warnings.extend(result.warnings)
            elif line.startswith('SecAction'):
                result = self._validate_secaction(line)
                if not result.is_valid:
                    result.waf_type = WAFType.MODSECURITY
                    return result
            elif line.startswith('SecMarker'):
                pass  # Always valid
            elif line.startswith('Sec'):
                pass  # Accept any Sec* directive — don't hard-fail on unknowns
            else:
                # Non-Sec line — warn but don't hard-fail (may be continuation)
                warnings.append(f"Unrecognised directive: {line[:60]}")

        return ValidationResult(
            is_valid=True,
            waf_type=WAFType.MODSECURITY,
            rule_id=self._extract_rule_id(rule),
            warnings=warnings if warnings else None
        )

    def _normalize_rule(self, rule: str) -> list[str]:
        """Normalize multi-line rules with backslash continuations."""
        rule = re.sub(r'\\\n\s*', ' ', rule)
        return [line for line in rule.split('\n') if line.strip()]

    def _validate_secrule(self, rule: str) -> ValidationResult:
        """Validate SecRule directive — lenient parsing."""
        warnings = []

        # Try quoted operator first
        pattern = r'^SecRule\s+(\S+)\s+"([^"]*)"(?:\s+"([^"]*)")?'
        match = re.match(pattern, rule)

        if not match:
            # Unquoted operator
            pattern2 = r'^SecRule\s+(\S+)\s+(\S+)(?:\s+"([^"]*)")?'
            match = re.match(pattern2, rule)

        if not match:
            return ValidationResult(
                is_valid=False,
                error_message='Cannot parse SecRule structure. Expected: SecRule VARIABLES "OPERATOR" "ACTIONS"'
            )

        variables_str = match.group(1)
        operator_str = match.group(2)
        actions_str = match.group(3) if match.lastindex >= 3 else ""

        # Variables: warn on unknown, never hard-fail
        for var in variables_str.split('|'):
            var = var.strip().lstrip('!').lstrip('&')
            base_var = re.split(r'[:\[]', var)[0].upper()
            if base_var and base_var not in self.KNOWN_VARIABLES and base_var not in {'TX', 'IP', 'GEO', 'SESSION', 'USER', 'ENV', 'RULE', 'GLOBAL', 'RESOURCE'}:
                warnings.append(f"Unknown variable: {base_var} (may be valid in newer ModSecurity)")

        # Operator: warn on unknown, never hard-fail
        op_clean = operator_str.lstrip('!')
        op_match = re.match(r'^(@\w+)', op_clean)
        if op_match:
            op_name = op_match.group(1)
            if op_name not in self.KNOWN_OPERATORS:
                warnings.append(f"Unknown operator: {op_name} (may be valid in your ModSecurity version)")
        # No @ prefix → plain string match, always valid

        # Actions: only hard-fail if `id` is missing
        if actions_str:
            act_result = self._validate_actions(actions_str)
            if not act_result.is_valid:
                return act_result
            if act_result.warnings:
                warnings.extend(act_result.warnings)
        else:
            # No actions block — warn but allow (chained rules may omit it)
            warnings.append("No actions block found (ok for chained rules)")

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_secaction(self, rule: str) -> ValidationResult:
        pattern = r'^SecAction\s+"([^"]*)"'
        match = re.match(pattern, rule)
        if not match:
            return ValidationResult(
                is_valid=False,
                error_message='Invalid SecAction syntax. Expected: SecAction "ACTIONS"'
            )
        return self._validate_actions(match.group(1))

    def _validate_actions(self, actions: str) -> ValidationResult:
        """Validate actions string — hard-fail only on missing `id`."""
        warnings = []
        has_id = False

        for action in self._split_actions(actions):
            action = action.strip()
            if not action:
                continue
            action_name = re.split(r"[:'(]", action)[0].lower()

            if action_name == 'id':
                has_id = True
            elif action_name == 't':
                t_match = re.match(r"t:(\w+)", action)
                if t_match and t_match.group(1) not in self.KNOWN_TRANSFORMATIONS:
                    warnings.append(f"Unknown transformation: {t_match.group(1)}")
            elif action_name not in self.KNOWN_ACTIONS:
                warnings.append(f"Unknown action: {action_name} (may be valid in newer CRS)")

        if not has_id:
            return ValidationResult(
                is_valid=False,
                error_message="Missing required action: id (every SecRule must have a unique id)"
            )

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _split_actions(self, actions: str) -> list[str]:
        """Split actions by comma, handling nested single quotes."""
        result, current, depth = [], "", 0
        for char in actions:
            if char == ',' and depth == 0:
                result.append(current)
                current = ""
            else:
                if char == "'":
                    depth = 1 - depth
                current += char
        if current:
            result.append(current)
        return result

    def _extract_rule_id(self, rule: str) -> Optional[int]:
        match = re.search(r'\bid:(\d+)', rule)
        return int(match.group(1)) if match else None


def validate_modsec_rule(rule: str) -> ValidationResult:
    return ModSecurityValidator().validate(rule)
