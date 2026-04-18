"""
Cloudflare WAF Expression Syntax Validator.

Validates Cloudflare WAF expressions (wirefilter syntax) offline.

Leniency policy (2026):
  Hard-fail: unbalanced parentheses/quotes, empty parens, missing value after operator.
  Warning:   unknown fields, unknown operators — Cloudflare adds new fields regularly.
  Pass:      everything else.
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

    # Known Cloudflare fields — updated for 2026 (Cloudflare WAF / Firewall Rules / Custom Rules)
    KNOWN_FIELDS = {
        # HTTP Request
        "http.request.uri", "http.request.uri.path", "http.request.uri.query",
        "http.request.method", "http.request.version",
        "http.request.full_uri", "http.request.body.raw", "http.request.body.truncated",
        "http.request.body.form", "http.request.body.mime",
        "http.request.body.size",
        "http.host", "http.user_agent", "http.cookie", "http.referer",
        "http.request.headers", "http.request.headers.names", "http.request.headers.values",
        "http.request.accepted_languages",
        "http.x_forwarded_for",
        # Response
        "http.response.code", "http.response.headers",
        # IP / Geo
        "ip.src", "ip.src.lat", "ip.src.lon", "ip.src.city", "ip.src.postal_code",
        "ip.src.metro_code", "ip.src.region", "ip.src.region_code",
        "ip.src.continent", "ip.src.country", "ip.src.asnum", "ip.src.is_in_european_union",
        "ip.src.subdivision_1_iso_code", "ip.src.subdivision_2_iso_code",
        "ip.geoip.asnum", "ip.geoip.continent", "ip.geoip.country",
        "ip.geoip.subdivision_1_iso_code", "ip.geoip.subdivision_2_iso_code",
        "ip.src.asn",
        # SSL/TLS
        "ssl", "ssl.protocol", "ssl.cipher",
        # Cloudflare platform fields
        "cf.bot_management.verified_bot", "cf.bot_management.score",
        "cf.bot_management.ja3_hash", "cf.bot_management.js_detection.passed",
        "cf.bot_management.detection_ids", "cf.bot_management.corporate_proxy",
        "cf.bot_management.static_resource", "cf.bot_management.ja4",
        "cf.client.bot", "cf.client_trust_score",
        "cf.threat_score", "cf.edge.server_port", "cf.edge.server_ip",
        "cf.verified_bot_category",
        "cf.waf.score", "cf.waf.score.sqli", "cf.waf.score.xss", "cf.waf.score.rce",
        "cf.waf.score.class.sqli", "cf.waf.score.class.xss", "cf.waf.score.class.rce",
        "cf.ray_id", "cf.worker.upstream_zone",
        "cf.zone.name", "cf.zone.id",
        "cf.tls_client_auth.cert_verified", "cf.tls_client_auth.cert_revoked",
        "cf.tls_client_auth.cert_issuer_dn", "cf.tls_client_auth.cert_subject_dn",
        "cf.tls_client_auth.cert_serial",
        "cf.hostname.metadata",
        # Raw
        "raw.http.request.uri", "raw.http.request.full_uri",
        "raw.http.request.body.raw",
    }

    KNOWN_OPERATORS = {
        "eq", "ne", "lt", "le", "gt", "ge",
        "contains", "starts_with", "ends_with", "matches",
        "in", "and", "or", "not", "xor",
        "any", "all", "none",
        "wildcard",
    }

    KNOWN_FUNCTIONS = {
        "any", "all", "concat", "ends_with", "len", "lookup_json_string",
        "lower", "regex_replace", "remove_bytes", "starts_with",
        "to_string", "upper", "url_decode", "uuidv4",
        "substring", "http.request.headers.get",
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

        # Hard-fail: unbalanced parentheses
        paren_result = self._check_balanced_parens(expression)
        if not paren_result.is_valid:
            paren_result.waf_type = WAFType.CLOUDFLARE
            return paren_result

        # Hard-fail: unterminated string
        quote_result = self._check_balanced_quotes(expression)
        if not quote_result.is_valid:
            quote_result.waf_type = WAFType.CLOUDFLARE
            return quote_result

        # Hard-fail: structurally broken expressions
        syntax_result = self._check_critical_syntax(expression)
        if not syntax_result.is_valid:
            syntax_result.waf_type = WAFType.CLOUDFLARE
            return syntax_result

        # Warning only: unknown fields (Cloudflare adds fields frequently)
        fields = self._extract_fields(expression)
        for field in fields:
            if field not in self.KNOWN_FIELDS:
                base_field = field.split('[')[0] if '[' in field else field
                if base_field not in self.KNOWN_FIELDS:
                    warnings.append(f"Unknown field: {field} (may be a newer Cloudflare field)")

        return ValidationResult(
            is_valid=True,
            waf_type=WAFType.CLOUDFLARE,
            warnings=warnings if warnings else None,
            metadata={"fields_used": list(fields)}
        )

    def _check_balanced_parens(self, expr: str) -> ValidationResult:
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

    def _check_critical_syntax(self, expr: str) -> ValidationResult:
        """Only the most critical structural checks — no false positives."""
        # Empty parens
        if re.search(r'\(\s*\)', expr):
            return ValidationResult(
                is_valid=False,
                error_message="Empty parentheses found"
            )

        # Comparison operator at end of expression with no value
        if re.search(r'\b(eq|ne|contains|matches|starts_with|ends_with)\s*$', expr.strip()):
            return ValidationResult(
                is_valid=False,
                error_message="Comparison operator has no value"
            )

        return ValidationResult(is_valid=True)

    def _extract_fields(self, expr: str) -> set[str]:
        """Extract field names from expression."""
        fields = set()
        # Remove string literals first to avoid false matches
        expr_clean = re.sub(r'"[^"]*"', '""', expr)
        expr_clean = re.sub(r"'[^']*'", "''", expr_clean)

        pattern = r'\b([a-z][a-z0-9_.]*(?:\[[^\]]+\])?)'
        matches = re.findall(pattern, expr_clean.lower())

        for match in matches:
            if match in self.KNOWN_OPERATORS or match in {'true', 'false', 'and', 'or', 'not', 'in', 'any', 'all'}:
                continue
            if '.' in match or match.startswith(('http', 'ip', 'ssl', 'cf', 'raw')):
                fields.add(match)

        return fields


def validate_cloudflare_rule(rule: str) -> ValidationResult:
    return CloudflareValidator().validate(rule)
