
# Blue Team System Prompt
BLUE_TEAM_SYSTEM_PROMPT = """You are a defensive security architect specializing in WAF rule engineering and threat mitigation. Your expertise includes:
- Crafting regex-based detection rules with minimal false positives
- Multi-layer defense strategies (signature + behavioral + anomaly detection)
- Encoding normalization and canonicalization techniques
- Attack pattern generalization without over-blocking legitimate traffic
- Performance-optimized rule sets for production environments

Your goal is to design robust, production-ready WAF rules that block attack vectors while maintaining application usability."""

def get_blue_team_waf_constraints(waf_name: str) -> str:
   waf_name_lower = (waf_name or "").lower().replace(" ", "")

   if "aws" in waf_name_lower:
      return """**AWS WAF-Specific Constraints**:
- Output valid AWS WAF JSON only.
- Each rule must be a single valid AWS WAF statement object.
- Do NOT wrap the output in higher-level objects such as Statement, Name, Rules, or VisibilityConfig.
- Use ONLY AWS WAF-supported text transformations from common supported sets such as: NONE, LOWERCASE, CMD_LINE, COMPRESS_WHITE_SPACE, HTML_ENTITY_DECODE, URL_DECODE, URL_DECODE_UNI, JS_DECODE, CSS_DECODE, BASE64_DECODE, HEX_DECODE, UTF8_TO_UNICODE, NORMALIZE_PATH, NORMALIZE_PATH_WIN, REMOVE_NULLS, REPLACE_COMMENTS.
- DO NOT use FULL_WIDTH_TO_HALF_WIDTH because it is not supported in this environment.
- Prefer structurally safe statements such as ByteMatchStatement, RegexMatchStatement, SqliMatchStatement, XssMatchStatement, AndStatement, OrStatement, NotStatement.
- If using ByteMatchStatement, keep PositionalConstraint limited to valid AWS values such as CONTAINS, STARTS_WITH, ENDS_WITH, EXACTLY, CONTAINS_WORD.
- Prefer valid FieldToMatch targets such as QueryString, UriPath, Body, SingleHeader, and AllQueryArguments when appropriate.
- Keep the output deployable as raw statement JSON, for example a single ByteMatchStatement, RegexMatchStatement, or XssMatchStatement object.
- Example ByteMatchStatement:
   {"ByteMatchStatement": {"SearchString": "pattern", "FieldToMatch": {"QueryString": {}}, "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}, {"Priority": 1, "Type": "LOWERCASE"}], "PositionalConstraint": "CONTAINS"}}
- Example RegexMatchStatement:
   {"RegexMatchStatement": {"RegexString": "(?i)<script[\\s>]", "FieldToMatch": {"QueryString": {}}, "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}]}}
- Example XssMatchStatement:
   {"XssMatchStatement": {"FieldToMatch": {"QueryString": {}}, "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}, {"Priority": 1, "Type": "HTML_ENTITY_DECODE"}]}}
- Before outputting, self-check that every field and transformation is valid AWS WAF syntax."""

   if "cloudflare" in waf_name_lower:
      return """**Cloudflare Free Plan Constraints**:
- Output a Cloudflare expression only, using simple wirefilter syntax.
- Keep the final output as a single deployable Cloudflare expression, for example `(http.request.uri contains "pattern")`.
- Assume Cloudflare Free plan limitations.
- Use ONLY basic comparison operators: contains, starts_with, ends_with, eq.
- Prefer fields like http.request.uri, http.request.uri.path, http.request.uri.query, http.request.body.raw, http.request.headers, http.user_agent.
- DO NOT use advanced operators or features such as matches, wildcard, regex functions, paid-only bot fields, or plan-dependent enterprise features unless absolutely unavoidable.
- Avoid complex function nesting.
- Keep expressions deployable on the free plan and easy to review.
- Example expression:
   (http.request.uri contains "pattern" or http.request.body.raw contains "pattern")
- Before outputting, self-check that the rule uses only basic operators and free-plan-compatible syntax."""

   if "naxsi" in waf_name_lower:
      return """**Naxsi-Specific Constraints**:
- Output Naxsi syntax only.
- DO NOT output ModSecurity syntax such as SecRule, SecAction, ctl, t:, phase:, deny, id inside quoted action lists, or chained ModSecurity directives.
- Prefer native Naxsi directives only: MainRule, BasicRule, CheckRule.
- MainRule should use Naxsi-native components like rx:/str:/d:, msg:, mz:, s:, id:...;
- BasicRule should use wl:... and mz:... only.
- CheckRule should use Naxsi threshold syntax only.
- For detection rules, include the Naxsi-native essentials: pattern (`rx:` or `str:`), match zone (`mz:`), score (`s:`), and unique `id:`.
- Example rule:
   MainRule "rx:pattern" "msg:Description" "mz:BODY|URL|ARGS" "s:$XSS:8" id:100001;
- End each Naxsi rule with ';'.
- Before outputting, self-check that no ModSecurity keywords or ModSecurity action syntax appear anywhere in the output."""

   if "modsec" in waf_name_lower:
      return """**ModSecurity-Specific Constraints**:
- Output ModSecurity syntax only.
- Latest ModSecurity version using deny instead of block action.
- Prefer SecRule or SecAction directives.
- Keep the output in deployable ModSecurity directive format, for example: `SecRule VARIABLES "OPERATOR" "id:XXXXX,phase:2,deny,status:403,msg:'Description',t:urlDecode,t:lowercase"`.
- Include a unique rule ID, a valid phase, and only valid ModSecurity actions and transformations.
- Example directive:
   SecRule VARIABLES "OPERATOR" "id:900001,phase:2,deny,status:403,msg:'Description',t:urlDecode,t:lowercase"
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

   waf_constraints = get_blue_team_waf_constraints(waf_name)
   
   """Generate user prompt for defense rule creation"""
   return f"""**CRITICAL SECURITY ALERT**: My WAF has been bypassed during authorized penetration testing.

**Environment:**
- WAF: {waf_name}
- Bypassed payloads clustered into {len(payload_clusters)} groups based on similarity and attack pattern:
{payload_cluster_string}

Generate PRODUCTION-GRADE defense rules to block these clusters of payloads, following these requirements:

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

def build_fix_rule_prompt(
   waf_name: str,
   rule: dict,
):
   waf_constraints = get_blue_team_waf_constraints(waf_name)
   return f"""You are fixing a WAF rule that failed syntax validation.

Target WAF: {waf_name}
WAF constraints:
{waf_constraints}

Validation error: {rule.get('validation_error')}
Original instructions: {rule.get('instructions', '')}
Invalid rule:
{rule.get('rule', '')}

Return valid JSON only with this shape:
{{
    "rule": "fixed rule",
    "instructions": "deployment instructions"
}}"""

def build_refine_system_prompt() -> str:
   return """You are an expert WAF rule engineer and security analyst. Your task is to:

1. Review and refine WAF rules for effectiveness and performance.
2. Deduplicate rules that have overlapping coverage.
3. Optimize patterns to avoid over-broad or slow matching.
4. Validate that the rules cover the bypassed payloads.
5. Avoid duplicating existing rules.

Return valid JSON only. No markdown. Be concise and technical."""


def build_refine_enhance_rules_prompt(
   waf_name: str,
   new_rules: str,
) -> str:
   waf_constraints = get_blue_team_waf_constraints(waf_name)
   return f"""
## Task: Review, validate, and refine candidate WAF rules

## Context:
- WAF: {waf_name}

## WAF constraints:
{waf_constraints}

## Candidate new rules:
{new_rules}

## Requirements:
1. Read all candidate rules and validate whether each rule uses the correct syntax for the target WAF.
2. Detect overlap between rules, especially cases where multiple rules block the same attack pattern, payload family, or normalized variant.
3. Remove unnecessary duplication and consolidate overlapping rules when one rule can cover the same responsibility more cleanly.
4. Fix invalid syntax, normalize inconsistent rule structure, and optimize patterns so the remaining rules are deployable and maintainable, referring to the WAF constraints above.
5. Avoid over-broad matching and reduce redundant coverage where possible without losing meaningful protection.
6. Keep only rules that are valid, useful, and production-ready for the target WAF.
7. If a rule should be removed, explain whether the reason is invalid syntax, duplicated responsibility, over-broad matching, or weak security value.

## Output format (JSON), no markdown, no code fences, valid JSON only, ensure valid escape like \\s \\( not \s \(:
{{
   "refined_rules": [
      {{
         "rule": "complete rule text",
         "instructions": "deployment instructions",
      }}
   ],
   "comparison_notes": "short summary of syntax fixes and overlap reduction",
   "coverage_analysis": "short statement describing what the final rule set covers"
}}
"""


def build_refine_sync_rules_prompt(
   waf_name: str,
   existing_rules: str,
   new_rules: str,
) -> str:
   waf_constraints = get_blue_team_waf_constraints(waf_name)
   return f"""
## Task: Sync new rules with existing rules, validate syntax, and refine the final rule set

## Context:
- WAF: {waf_name}

## WAF constraints:
{waf_constraints}

## Existing rules:
{existing_rules}

## New candidate rules:
{new_rules}

## Requirements:
1. Compare the new candidate rules with the existing rules to detect duplicate coverage, overlapping responsibility, or equivalent syntax.
2. Merge or consolidate rules when multiple rules block the same attack pattern, payload family, or normalized variant.
3. Keep a new rule only if it adds meaningful coverage, improves precision, or fixes an issue in an existing rule.
4. Validate that every rule in the final output uses correct syntax for the target WAF and fully respects the WAF constraints above.
5. Fix invalid syntax, reduce redundancy, and optimize over-broad or conflicting rules so the final rule set is deployable and maintainable.
6. Remove any rule that is redundant, conflicting, too broad, low-value, or not deployable.
7. Return only the final production-ready rules after synchronization and refinement that will enhance the existing rules, do not response the existing rules.

## Output format (JSON), no markdown, no code fences, valid JSON only, ensure valid escape like \\s \\( not \s \(:
{{
   "refined_rules": [
      {{
         "rule": "complete rule text",
         "instructions": "deployment instructions",
      }}
   ],
   "comparison_notes": "short summary of synchronization decisions, syntax fixes, and overlap reduction",
   "coverage_analysis": "short statement describing what the final synchronized rule set covers"
}}
"""
