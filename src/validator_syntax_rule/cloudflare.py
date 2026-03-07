"""
Cloudflare WAF Expression Syntax Validator.

Validates Cloudflare WAF expressions (wirefilter syntax) offline.
"""

import re
from typing import Optional

from .base import BaseValidator, ValidationResult, WAFType


class CloudflareValidator(BaseValidator):
    """
    Validate Cloudflare WAF expression syntax offline.

    Cloudflare uses wirefilter syntax (Wireshark-like expressions).
    Example: (http.request.uri contains "<script>" and not cf.bot_management.verified_bot)

    Usage:
        validator = CloudflareValidator()
        result = validator.validate('(http.request.uri contains "test")')
    """

    # Valid Cloudflare fields
    VALID_FIELDS = {
        # HTTP Request fields
        "http.request.uri", "http.request.uri.path", "http.request.uri.query",
        "http.request.method", "http.request.version",
        "http.request.full_uri", "http.request.body.raw", "http.request.body.truncated",
        "http.request.body.form", "http.request.body.mime",
        "http.host", "http.user_agent", "http.cookie", "http.referer",
        "http.request.headers", "http.request.headers.names", "http.request.headers.values",
        "http.request.accepted_languages",
        # IP fields
        "ip.src", "ip.src.lat", "ip.src.lon", "ip.src.city", "ip.src.postal_code",
        "ip.src.metro_code", "ip.src.region", "ip.src.region_code",
        "ip.src.continent", "ip.src.country", "ip.src.asnum", "ip.src.is_in_european_union",
        "ip.geoip.asnum", "ip.geoip.continent", "ip.geoip.country",
        "ip.geoip.subdivision_1_iso_code", "ip.geoip.subdivision_2_iso_code",
        # SSL/TLS fields
        "ssl", "ssl.protocol",
        # Cloudflare fields
        "cf.bot_management.verified_bot", "cf.bot_management.score",
        "cf.bot_management.ja3_hash", "cf.bot_management.js_detection.passed",
        "cf.client.bot", "cf.client_trust_score",
        "cf.threat_score", "cf.edge.server_port",
        "cf.verified_bot_category", "cf.waf.score", "cf.waf.score.sqli",
        "cf.waf.score.xss", "cf.waf.score.rce",
        "cf.ray_id", "cf.worker.upstream_zone",
        # Raw fields
        "raw.http.request.uri", "raw.http.request.full_uri",
    }

    # Valid operators
    VALID_OPERATORS = {
        # Comparison
        "eq", "ne", "lt", "le", "gt", "ge",
        # String matching
        "contains", "starts_with", "ends_with", "matches",
        # Set membership
        "in",
        # Logical
        "and", "or", "not", "xor",
        # Special
        "any", "all", "none",
    }

    # Valid functions
    VALID_FUNCTIONS = {
        "any", "all", "concat", "ends_with", "len", "lookup_json_string",
        "lower", "regex_replace", "remove_bytes", "starts_with",
        "to_string", "upper", "url_decode", "uuidv4",
    }

    def get_waf_type(self) -> WAFType:
        return WAFType.CLOUDFLARE

    def validate(self, expression: str) -> ValidationResult:
        """Validate a Cloudflare WAF expression."""
        expression = expression.strip()

        if not expression:
            return ValidationResult(
                is_valid=False,
                waf_type=WAFType.CLOUDFLARE,
                error_message="Empty expression"
            )

        warnings = []

        # Check balanced parentheses
        paren_result = self._check_balanced_parens(expression)
        if not paren_result.is_valid:
            paren_result.waf_type = WAFType.CLOUDFLARE
            return paren_result

        # Check balanced quotes
        quote_result = self._check_balanced_quotes(expression)
        if not quote_result.is_valid:
            quote_result.waf_type = WAFType.CLOUDFLARE
            return quote_result

        # Extract and validate fields
        fields = self._extract_fields(expression)
        for field in fields:
            if field not in self.VALID_FIELDS:
                base_field = field.split('[')[0] if '[' in field else field
                if base_field not in self.VALID_FIELDS:
                    warnings.append(f"Unknown field: {field}")

        # Check for common syntax errors
        syntax_result = self._check_common_syntax(expression)
        if not syntax_result.is_valid:
            syntax_result.waf_type = WAFType.CLOUDFLARE
            return syntax_result
        if syntax_result.warnings:
            warnings.extend(syntax_result.warnings)

        # Validate operators usage
        op_result = self._validate_operators(expression)
        if not op_result.is_valid:
            op_result.waf_type = WAFType.CLOUDFLARE
            return op_result

        return ValidationResult(
            is_valid=True,
            waf_type=WAFType.CLOUDFLARE,
            warnings=warnings if warnings else None,
            metadata={"fields_used": list(fields)}
        )

    def _check_balanced_parens(self, expr: str) -> ValidationResult:
        """Check for balanced parentheses."""
        depth = 0
        in_string = False
        string_char = None

        for i, char in enumerate(expr):
            if char in '"\'':
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False
            elif not in_string:
                if char == '(':
                    depth += 1
                elif char == ')':
                    depth -= 1
                    if depth < 0:
                        return ValidationResult(
                            is_valid=False,
                            error_message=f"Unmatched closing parenthesis at position {i}"
                        )

        if depth != 0:
            return ValidationResult(
                is_valid=False,
                error_message=f"Unbalanced parentheses: {depth} unclosed"
            )
        return ValidationResult(is_valid=True)

    def _check_balanced_quotes(self, expr: str) -> ValidationResult:
        """Check for balanced quotes."""
        in_string = False
        string_char = None
        escape_next = False

        for char in expr:
            if escape_next:
                escape_next = False
                continue
            if char == '\\':
                escape_next = True
                continue
            if char in '"\'':
                if not in_string:
                    in_string = True
                    string_char = char
                elif char == string_char:
                    in_string = False

        if in_string:
            return ValidationResult(
                is_valid=False,
                error_message="Unterminated string literal"
            )
        return ValidationResult(is_valid=True)

    def _extract_fields(self, expr: str) -> set[str]:
        """Extract field names from expression."""
        fields = set()
        pattern = r'\b([a-z][a-z0-9_.]*(?:\[[^\]]+\])?)'
        matches = re.findall(pattern, expr.lower())

        for match in matches:
            if match not in self.VALID_OPERATORS and match not in {'true', 'false'}:
                if '.' in match or match.startswith(('http', 'ip', 'ssl', 'cf', 'raw')):
                    fields.add(match)

        return fields

    def _check_common_syntax(self, expr: str) -> ValidationResult:
        """Check for common syntax errors."""
        warnings = []

        # Check for empty conditions
        if re.search(r'\(\s*\)', expr):
            return ValidationResult(
                is_valid=False,
                error_message="Empty parentheses found"
            )

        # Check for double operators
        if re.search(r'\b(and|or)\s+(and|or)\b', expr, re.IGNORECASE):
            return ValidationResult(
                is_valid=False,
                error_message="Double logical operators found"
            )

        # Check for missing operators between conditions
        if re.search(r'\)\s*\(', expr):
            warnings.append("Possible missing operator between conditions")

        # Check for comparison without value
        if re.search(r'\b(eq|ne|contains|matches)\s*[)\s]*$', expr):
            return ValidationResult(
                is_valid=False,
                error_message="Comparison operator missing value"
            )

        return ValidationResult(is_valid=True, warnings=warnings if warnings else None)

    def _validate_operators(self, expr: str) -> ValidationResult:
        """Validate operator usage in expression."""
        # Remove string literals to avoid false positives
        expr_no_strings = re.sub(r'"[^"]*"', '""', expr)
        expr_no_strings = re.sub(r"'[^']*'", "''", expr_no_strings)

        # Find all word tokens
        tokens = re.findall(r'\b([a-z_]+)\b', expr_no_strings.lower())

        for token in tokens:
            if '.' in token or token.startswith(('http', 'ip', 'ssl', 'cf', 'raw')):
                continue
            if token in self.VALID_OPERATORS:
                continue
            if token in {'true', 'false', 'in'}:
                continue
            if token in self.VALID_FUNCTIONS:
                continue

        return ValidationResult(is_valid=True)


def validate_cloudflare_rule(rule: str) -> ValidationResult:
    """
    Convenience function to validate a Cloudflare WAF expression.

    Args:
        rule: Cloudflare expression string

    Returns:
        ValidationResult
    """
    return CloudflareValidator().validate(rule)
