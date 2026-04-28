"""
LLM prompts for payload generation and defense rule creation using via OpenAI's API.
"""

# Red Team System Prompt
RED_TEAM_SYSTEM_PROMPT = """You are an elite red team operator and WAF bypass specialist with deep expertise in:
- Advanced payload obfuscation and encoding techniques (Unicode, hex, octal, base64, double encoding)
- WAF evasion methods (case manipulation, comment injection, null bytes, whitespace abuse)
- Polyglot payloads that work across multiple contexts
- Protocol-level attacks and HTTP parameter pollution
- Signature-based detection bypass using mutation and fragmentation
- Context-aware payload crafting based on specific WAF vendor fingerprints

Your goal is to generate sophisticated, real-world attack payloads that can expose WAF weaknesses before malicious actors exploit them."""

def get_red_team_user_prompt(waf_name, attack_type, num_payloads):
   """Generate user prompt for payload generation"""
   return f"""I'm conducting authorized penetration testing on my production WAF. Target details:
- Attack Vector: {attack_type}
- WAF Fingerprint: {waf_name}

Generate {num_payloads} ADVANCED payloads designed to bypass this specific WAF using:

1. **Obfuscation Techniques**: Mix encoding methods (URL encoding, Unicode normalization, hex escaping, HTML entities)
2. **Evasion Strategies**:
   - Case variation (e.g., sCrIpT, <ScRiPt>)
   - Comment injection (e.g., <scr<!---->ipt>, <scr/**/ipt>)
   - Null byte injection (e.g., %00, \\x00)
   - Whitespace manipulation (tabs, newlines, CR/LF)

3. **Advanced Techniques**:
   - Protocol-level tricks (HTTP parameter pollution, chunked encoding)
   - Polyglot payloads (valid in multiple contexts)
   - Timing-based attacks for blind scenarios
   - Fragmentation across multiple parameters

4. **WAF-Specific Bypasses**: Target known weaknesses based on the WAF fingerprint

**CRITICAL**: Generate payloads that:
- Avoid common blacklist patterns (alert, script, SELECT, UNION)
- Use rare but valid syntax variants
- Leverage edge cases in parsers
- Mix multiple evasion techniques per payload

For each payload, provide tactical deployment instructions."""

# Blue Team System Prompt
BLUE_TEAM_SYSTEM_PROMPT = """You are a defensive security architect specializing in WAF rule engineering and threat mitigation. Your expertise includes:
- Crafting regex-based detection rules with minimal false positives
- Multi-layer defense strategies (signature + behavioral + anomaly detection)
- Encoding normalization and canonicalization techniques
- Attack pattern generalization without over-blocking legitimate traffic
- Performance-optimized rule sets for production environments

Your goal is to design robust, production-ready WAF rules that block attack vectors while maintaining application usability."""

def _get_blue_team_waf_constraints(waf_name: str) -> str:
   waf_name_lower = (waf_name or "").lower().replace(" ", "")

   if "aws" in waf_name_lower:
      return """**AWS WAF-Specific Constraints**:
- Output valid AWS WAF JSON only.
- Use ONLY AWS WAF-supported text transformations from common supported sets such as: NONE, LOWERCASE, CMD_LINE, COMPRESS_WHITE_SPACE, HTML_ENTITY_DECODE, URL_DECODE, URL_DECODE_UNI, JS_DECODE, CSS_DECODE, BASE64_DECODE, HEX_DECODE, UTF8_TO_UNICODE, NORMALIZE_PATH, NORMALIZE_PATH_WIN, REMOVE_NULLS, REPLACE_COMMENTS.
- DO NOT use FULL_WIDTH_TO_HALF_WIDTH because it is not supported in this environment.
- Prefer structurally safe statements such as ByteMatchStatement, RegexMatchStatement, SqliMatchStatement, XssMatchStatement, AndStatement, OrStatement, NotStatement.
- If using ByteMatchStatement, keep PositionalConstraint limited to valid AWS values such as CONTAINS, STARTS_WITH, ENDS_WITH, EXACTLY, CONTAINS_WORD.
- Include VisibilityConfig when possible.
- Before outputting, self-check that every field and transformation is valid AWS WAF syntax."""

   if "cloudflare" in waf_name_lower:
      return """**Cloudflare Free Plan Constraints**:
- Output a Cloudflare expression only, using simple wirefilter syntax.
- Assume Cloudflare Free plan limitations.
- Use ONLY basic comparison operators: contains, starts_with, ends_with, eq.
- Prefer fields like http.request.uri, http.request.uri.path, http.request.uri.query, http.request.body.raw, http.request.headers, http.user_agent.
- DO NOT use advanced operators or features such as matches, wildcard, regex functions, paid-only bot fields, or plan-dependent enterprise features unless absolutely unavoidable.
- Avoid complex function nesting.
- Keep expressions deployable on the free plan and easy to review.
- Before outputting, self-check that the rule uses only basic operators and free-plan-compatible syntax."""

   if "naxsi" in waf_name_lower:
      return """**Naxsi-Specific Constraints**:
- Output Naxsi syntax only.
- DO NOT output ModSecurity syntax such as SecRule, SecAction, ctl, t:, phase:, deny, id inside quoted action lists, or chained ModSecurity directives.
- Prefer native Naxsi directives only: MainRule, BasicRule, CheckRule.
- MainRule should use Naxsi-native components like rx:/str:/d:, msg:, mz:, s:, id:...;
- BasicRule should use wl:... and mz:... only.
- CheckRule should use Naxsi threshold syntax only.
- End each Naxsi rule with ';'.
- Before outputting, self-check that no ModSecurity keywords or ModSecurity action syntax appear anywhere in the output."""

   if "modsec" in waf_name_lower:
      return """**ModSecurity-Specific Constraints**:
- Output ModSecurity syntax only.
- Prefer SecRule or SecAction directives.
- Use valid ModSecurity transformations and actions only.
- Do not output AWS JSON, Cloudflare expressions, or Naxsi MainRule/BasicRule syntax.
- Before outputting, self-check that every rule contains valid ModSecurity directive structure."""

   return """**WAF-Specific Constraints**:
- Output rules strictly in the target WAF syntax.
- Do not mix syntax across different WAF engines.
- Before outputting, self-check that the rule format matches the target WAF only."""

def get_blue_team_user_prompt(waf_name, payload_clusters:list[dict]):
   payload_cluster_string = ""
   for c in payload_clusters:
      payload_cluster_string += f"\tCluster {c['cluster_id']} ({c['size']} payloads):\n"
      for p in c['payloads']:
         payload_cluster_string += f"\t\t{p}\n"

   waf_constraints = _get_blue_team_waf_constraints(waf_name)
   
   """Generate user prompt for defense rule creation"""
   return f"""**CRITICAL SECURITY ALERT**: My WAF has been bypassed during authorized penetration testing.

**Environment:**
- WAF: {waf_name}
- Bypassed Payloads by clusters:
{payload_cluster_string}

Generate PRODUCTION-GRADE defense rules to block these bypasses:

1. **Multi-Layer Detection**: Create rules that detect:
   - Raw pattern matching (regex)
   - Normalized/decoded variants (URL decoding, Unicode normalization)
   - Obfuscation techniques (comment injection, case variations)
   - Anomaly patterns (unusual character sequences, excessive encoding)

2. **Rule Requirements**:
   - Match both obvious and obfuscated forms
   - Include pre-processing steps (normalize, decode, lowercase)
   - Minimize false positives with negative lookaheads
   - Specify rule severity and recommended action (BLOCK/LOG/CHALLENGE)

3. **Coverage Strategy**: Generalize patterns to catch variants without overfitting to specific payloads.

4. **Target WAF Guardrails**:
{waf_constraints}

5. **Mandatory Self-Check Before Final Output**:
   - Verify the syntax belongs to the target WAF only.
   - Verify no unsupported transformation, operator, or directive is present.
   - If a desired normalization step is unsupported by the target WAF, replace it with the closest supported alternative instead of inventing a new syntax.
   - Prefer a simpler valid rule over a more advanced but potentially invalid rule.

6. **Multi-Layer URL Encoding**: When generating rules, always account for multi-layer URL encoding by applying repeated URL-decoding transformations, e.g. t:urlDecodeUni multiple times, so payloads encoded two or more times such as %25253C...%25253E are normalized before regex matching.

The WAF format instruction will follow — generate rules ONLY in that specified format."""

def build_adaptive_prompt(waf_name, attack_type, blocked_examples, passed_examples, technique):
      """Build Phase 3 style prompt with BLOCKED/PASSED examples"""
      
      # Format examples
      blocked_str = "\n".join([f"  - {p['payload']}" for p in blocked_examples]) if blocked_examples else "  (none)"
      passed_str = "\n".join([f"  - {p['payload']}" for p in passed_examples]) if passed_examples else "  (none)"
      
      attack_str = "SQL injection" if attack_type == "SQLI" else "XSS"
      
      prompt = f"""Generate WAF-evasion payloads.

Target: {attack_str} on {waf_name}.
Technique: {technique}

[Observations]
- BLOCKED: 
{blocked_str}
- PASSED:
{passed_str}

Instruction: Generate a NEW payload using the target technique, learning from the PASSED examples if available. Output ONLY the payload."""
   
      return prompt