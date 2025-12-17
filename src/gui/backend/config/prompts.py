"""
LLM prompts for payload generation and defense rule creation
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

def get_red_team_user_prompt(waf_info, attack_type, num_payloads):
    """Generate user prompt for payload generation"""
    return f"""I'm conducting authorized penetration testing on my production WAF. Target details:
- Attack Vector: {attack_type}
- WAF Fingerprint: {waf_info}

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

def get_blue_team_user_prompt(waf_info, bypassed_payloads, bypassed_instructions, num_rules):
    """Generate user prompt for defense rule creation"""
    return f"""**CRITICAL SECURITY ALERT**: My WAF has been bypassed during authorized penetration testing.

**Environment:**
- WAF: {waf_info}
- Bypassed Payloads: {bypassed_payloads}
- Attack Techniques Used: {bypassed_instructions}

Generate {num_rules} PRODUCTION-GRADE defense rules to block these bypasses:

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

3. **Implementation Details**:
   - Provide rules in ModSecurity SecRule format
   - Include transformation functions (t:urlDecode, t:lowercase, etc.)
   - Specify phase (REQUEST_HEADERS, REQUEST_BODY, etc.)
   - Add actionable deployment instructions

4. **Coverage Strategy**: Generalize patterns to catch variants without overfitting to specific payloads.

**FORMAT**: For each rule, provide:
- SecRule syntax
- Transformation pipeline
- Severity level
- Deployment phase
- Testing methodology"""

def build_adaptive_prompt(waf_info, attack_type, blocked_examples, passed_examples, technique):
    """Build Phase 3 style prompt with BLOCKED/PASSED examples"""
    
    # Format examples
    blocked_str = "\n".join([f"  - {p['payload']}" for p in blocked_examples]) if blocked_examples else "  (none)"
    passed_str = "\n".join([f"  - {p['payload']}" for p in passed_examples]) if passed_examples else "  (none)"
    
    attack_str = "SQL injection" if attack_type == "SQLI" else "XSS"
    
    prompt = f"""Generate WAF-evasion payloads.

Target: {attack_str} on {waf_info}.
Technique: {technique}

[Observations]
- BLOCKED: 
{blocked_str}
- PASSED:
{passed_str}

Instruction: Generate a NEW payload using the target technique, learning from the PASSED examples if available. Output ONLY the payload."""
    
    return prompt