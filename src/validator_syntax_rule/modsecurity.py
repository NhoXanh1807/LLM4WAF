"""
ModSecurity Rule Syntax Validator.

Validates ModSecurity SecRule syntax offline.
Supports both pymodsecurity (libmodsecurity) and pure Python fallback.
"""

import re
from typing import Optional

from .base import BaseValidator, ValidationResult, WAFType


class ModSecurityValidator(BaseValidator):
    """
    Validate ModSecurity SecRule syntax offline.

    Supports two backends:
    1. pymodsecurity (requires libmodsecurity) - most accurate
    2. Pure Python regex parser - fallback, less accurate

    Usage:
        validator = ModSecurityValidator()
        result = validator.validate('SecRule ARGS "@rx <script>" "id:1,deny"')
    """

    VALID_VARIABLES = {
        # Request variables
        "ARGS", "ARGS_GET", "ARGS_POST", "ARGS_NAMES", "ARGS_GET_NAMES", "ARGS_POST_NAMES",
        "REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME", "REQUEST_BASENAME",
        "REQUEST_LINE", "REQUEST_METHOD", "REQUEST_PROTOCOL", "REQUEST_BODY",
        "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES", "REQUEST_COOKIES", "REQUEST_COOKIES_NAMES",
        "QUERY_STRING", "AUTH_TYPE", "FULL_REQUEST", "FULL_REQUEST_LENGTH",
        "FILES", "FILES_NAMES", "FILES_SIZES", "FILES_COMBINED_SIZE",
        "MULTIPART_STRICT_ERROR", "MULTIPART_UNMATCHED_BOUNDARY",
        # Response variables
        "RESPONSE_BODY", "RESPONSE_CONTENT_LENGTH", "RESPONSE_CONTENT_TYPE",
        "RESPONSE_HEADERS", "RESPONSE_HEADERS_NAMES", "RESPONSE_PROTOCOL",
        "RESPONSE_STATUS",
        # Server variables
        "REMOTE_ADDR", "REMOTE_HOST", "REMOTE_PORT", "REMOTE_USER",
        "SERVER_ADDR", "SERVER_NAME", "SERVER_PORT",
        # Transaction variables
        "TX", "IP", "GEO", "SESSION", "USER",
        # Special variables
        "MATCHED_VAR", "MATCHED_VAR_NAME", "MATCHED_VARS", "MATCHED_VARS_NAMES",
        "RULE", "ENV", "DURATION", "TIME", "TIME_DAY", "TIME_EPOCH",
        "TIME_HOUR", "TIME_MIN", "TIME_MON", "TIME_SEC", "TIME_WDAY", "TIME_YEAR",
        "UNIQUE_ID", "URLENCODED_ERROR", "WEBSERVER_ERROR_LOG",
        "XML", "REQBODY_ERROR", "REQBODY_ERROR_MSG", "REQBODY_PROCESSOR",
    }

    VALID_OPERATORS = {
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
    }

    VALID_ACTIONS = {
        # Disruptive actions
        "block", "deny", "drop", "allow", "pass", "pause", "proxy", "redirect",
        # Non-disruptive actions
        "capture", "chain", "ctl", "exec", "expirevar", "id", "initcol",
        "log", "logdata", "msg", "multiMatch", "nolog", "noauditlog", "auditlog",
        "phase", "prepend", "append", "sanitiseArg", "sanitiseMatched",
        "sanitiseMatchedBytes", "sanitiseRequestHeader", "sanitiseResponseHeader",
        "setuid", "setrsc", "setsid", "setenv", "setvar", "severity", "skip",
        "skipAfter", "status", "tag", "ver", "xmlns", "t", "rev", "maturity",
        "accuracy",
    }

    VALID_TRANSFORMATIONS = {
        "none", "lowercase", "uppercase", "urlDecode", "urlDecodeUni",
        "urlEncode", "htmlEntityDecode", "base64Decode", "base64DecodeExt",
        "base64Encode", "hexDecode", "hexEncode", "jsDecode", "cssDecode",
        "cmdLine", "compressWhitespace", "length", "md5", "sha1",
        "normalisePath", "normalisePathWin", "normalizePath", "normalizePathWin",
        "parityEven7bit", "parityOdd7bit", "parityZero7bit",
        "removeNulls", "removeWhitespace", "removeComments", "removeCommentsChar",
        "replaceComments", "replaceNulls", "sqlHexDecode", "trimLeft", "trimRight",
        "trim", "utf8toUnicode",
    }

    VALID_DIRECTIVES = {
        "SecRuleEngine", "SecRequestBodyAccess", "SecResponseBodyAccess",
        "SecRequestBodyLimit", "SecRequestBodyNoFilesLimit",
        "SecRequestBodyLimitAction", "SecResponseBodyLimit",
        "SecResponseBodyLimitAction", "SecResponseBodyMimeType",
        "SecTmpDir", "SecDataDir", "SecDebugLog", "SecDebugLogLevel",
        "SecAuditEngine", "SecAuditLog", "SecAuditLogParts",
        "SecAuditLogRelevantStatus", "SecAuditLogType",
        "SecArgumentSeparator", "SecCookieFormat", "SecStatusEngine",
        "SecServerSignature", "SecComponentSignature",
        "SecDefaultAction", "SecRuleRemoveById", "SecRuleRemoveByTag",
        "SecRuleUpdateActionById", "SecRuleUpdateTargetById",
        "SecHashEngine", "SecHashKey", "SecHashParam", "SecHashMethodRx",
        "SecCollectionTimeout", "SecContentInjection",
        "SecStreamInBodyInspection", "SecStreamOutBodyInspection",
        "SecInterceptOnError", "SecPcreMatchLimit", "SecPcreMatchLimitRecursion",
        "SecUnicodeMapFile", "SecGeoLookupDb", "SecGsbLookupDb",
    }

    def __init__(self, use_libmodsecurity: bool = True):
        """
        Initialize validator.

        Args:
            use_libmodsecurity: Try to use pymodsecurity if available
        """
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
        """Validate using libmodsecurity (pymodsecurity)."""
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
        """Validate using pure Python regex parser."""
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
                result = self._validate_secmarker(line)
                if not result.is_valid:
                    result.waf_type = WAFType.MODSECURITY
                    return result
            elif line.startswith('Sec'):
                result = self._validate_sec_directive(line)
                if not result.is_valid:
                    result.waf_type = WAFType.MODSECURITY
                    return result
            else:
                return ValidationResult(
                    is_valid=False,
                    waf_type=WAFType.MODSECURITY,
                    error_message=f"Unknown directive: {line[:50]}..."
                )

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
        """Validate SecRule directive."""
        warnings = []
        pattern = r'^SecRule\s+([^\s]+)\s+"([^"]*)"(?:\s+"([^"]*)")?'
        match = re.match(pattern, rule)

        if not match:
            pattern2 = r'^SecRule\s+([^\s]+)\s+([^\s"]+)(?:\s+"([^"]*)")?'
            match = re.match(pattern2, rule)
            if not match:
                return ValidationResult(
                    is_valid=False,
                    error_message='Invalid SecRule syntax. Expected: SecRule VARIABLES "OPERATOR" "ACTIONS"'
                )

        variables = match.group(1)
        operator = match.group(2)
        actions = match.group(3) if match.lastindex >= 3 else ""

        var_result = self._validate_variables(variables)
        if not var_result.is_valid:
            return var_result
        if var_result.warnings:
            warnings.extend(var_result.warnings)

        op_result = self._validate_operator(operator)
        if not op_result.is_valid:
            return op_result

        if actions:
            act_result = self._validate_actions(actions)
            if not act_result.is_valid:
                return act_result
            if act_result.warnings:
                warnings.extend(act_result.warnings)

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_secaction(self, rule: str) -> ValidationResult:
        """Validate SecAction directive."""
        pattern = r'^SecAction\s+"([^"]*)"'
        match = re.match(pattern, rule)
        if not match:
            return ValidationResult(
                is_valid=False,
                error_message='Invalid SecAction syntax. Expected: SecAction "ACTIONS"'
            )
        return self._validate_actions(match.group(1))

    def _validate_secmarker(self, rule: str) -> ValidationResult:
        """Validate SecMarker directive."""
        pattern = r'^SecMarker\s+"?([^"\s]+)"?'
        match = re.match(pattern, rule)
        if not match:
            return ValidationResult(
                is_valid=False,
                error_message='Invalid SecMarker syntax. Expected: SecMarker "MARKER_NAME"'
            )
        return ValidationResult(is_valid=True)

    def _validate_sec_directive(self, rule: str) -> ValidationResult:
        """Validate other Sec* directives."""
        directive = rule.split()[0]
        if directive not in self.VALID_DIRECTIVES:
            return ValidationResult(
                is_valid=False,
                error_message=f"Unknown directive: {directive}"
            )
        return ValidationResult(is_valid=True)

    def _validate_variables(self, variables: str) -> ValidationResult:
        """Validate SecRule variables."""
        warnings = []
        for var in variables.split('|'):
            var = var.strip()
            if var.startswith('!'):
                var = var[1:]
            if var.startswith('&'):
                var = var[1:]
            base_var = re.split(r'[:\[]', var)[0].upper()
            if base_var in {'TX', 'IP', 'GEO', 'SESSION', 'USER', 'ENV', 'RULE'}:
                continue
            if base_var not in self.VALID_VARIABLES:
                warnings.append(f"Unknown variable: {base_var}")
        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_operator(self, operator: str) -> ValidationResult:
        """Validate SecRule operator."""
        if operator.startswith('!'):
            operator = operator[1:]
        op_match = re.match(r'^(@\w+)', operator)
        if op_match:
            op_name = op_match.group(1)
            if op_name not in self.VALID_OPERATORS:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Unknown operator: {op_name}"
                )
        return ValidationResult(is_valid=True)

    def _validate_actions(self, actions: str) -> ValidationResult:
        """Validate SecRule actions."""
        warnings = []
        has_id = False
        has_phase = False

        for action in self._split_actions(actions):
            action = action.strip()
            if not action:
                continue
            action_name = re.split(r"[:'(]", action)[0].lower()

            if action_name == 'id':
                has_id = True
            elif action_name == 'phase':
                has_phase = True
            elif action_name == 't':
                t_match = re.match(r"t:(\w+)", action)
                if t_match and t_match.group(1) not in self.VALID_TRANSFORMATIONS:
                    warnings.append(f"Unknown transformation: {t_match.group(1)}")
            elif action_name not in self.VALID_ACTIONS:
                warnings.append(f"Unknown action: {action_name}")

        if not has_id:
            return ValidationResult(
                is_valid=False,
                error_message="Missing required action: id"
            )
        if not has_phase:
            warnings.append("Missing phase action (defaults to phase:2)")

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _split_actions(self, actions: str) -> list[str]:
        """Split actions by comma, handling nested quotes."""
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
        """Extract rule ID from rule string."""
        match = re.search(r'\bid:(\d+)', rule)
        return int(match.group(1)) if match else None


def validate_modsec_rule(rule: str) -> ValidationResult:
    """
    Convenience function to validate a ModSecurity rule.

    Args:
        rule: ModSecurity rule string

    Returns:
        ValidationResult
    """
    return ModSecurityValidator().validate(rule)
