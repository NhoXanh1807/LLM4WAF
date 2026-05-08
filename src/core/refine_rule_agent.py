"""
Rule refinement helpers for WAF rule refinement and comparison.

Pipeline position:
    [1] LLM + RAG -> Generate Rules
    [2] Syntax Validator -> Check syntax
    [3] Refine Rule Agent -> Refine & Compare (this module)
    [4] Output final rules
"""

import json
from dataclasses import dataclass, field
from typing import Optional
from services_external.llm import claude_completion

DEFAULT_MODEL = "claude-sonnet-4-6"
SYSTEM_PROMPT = """You are an expert WAF rule engineer and security analyst. Your task is to:

1. Review and refine WAF rules for effectiveness and performance.
2. Deduplicate rules that have overlapping coverage.
3. Optimize patterns to avoid over-broad or slow matching.
4. Validate that the rules cover the bypassed payloads.
5. Avoid duplicating existing rules.

Return valid JSON only. No markdown. Be concise and technical."""

REFINEMENT_PROMPT_TEMPLATE = """
## Nhiệm vụ: Xác thực WAF rules syntax và tinh chỉnh
## Context

### WAF Type:
{waf_type}

### Bypassed Payloads (must be blocked):
{bypassed_payloads}

### Newly Generated Rules:
{new_rules}

### Existing Rules (avoid duplicates):
{existing_rules}

### Instructions:
1. Validate rule coverage against the payloads.
2. Remove or merge duplicates.
3. Optimize patterns for performance and precision.
4. Ensure the rules remain in the correct WAF syntax.
5. Return only deployable rules.

### Output Format (JSON):
{{
    "refined_rules": [
        {{
            "rule": "complete rule text",
            "instructions": "deployment instructions",
            "changes_made": "what changed or why it was kept"
        }}
    ],
    "removed_rules": [
        {{
            "original_rule": "removed rule text",
            "reason": "duplicate, ineffective, or superseded"
        }}
    ],
    "comparison_notes": "short summary",
    "coverage_analysis": "short coverage statement"
}}
"""

REFINE_PROMPT = """
## Nhiệm vụ: Xác thực WAF rules syntax và tinh chỉnh

## Context:
- WAF : {waf_name}
- WAF contraints and guardrails:
Tôi có một bộ rules mới 
"""

SYNC_RULES_PROMPT = """
"""

@dataclass
class RefinementResult:
    success: bool
    refined_rules: list[dict] = field(default_factory=list)
    removed_duplicates: int = 0
    improvements_made: list[str] = field(default_factory=list)
    comparison_notes: str = ""
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "refined_rules": self.refined_rules,
            "removed_duplicates": self.removed_duplicates,
            "improvements_made": self.improvements_made,
            "comparison_notes": self.comparison_notes,
            "error_message": self.error_message,
        }


def refine_rules(
    new_rules: list[dict],
    bypassed_payloads: list[str],
    existing_rules: Optional[list[dict]] = None,
    waf_type: str = "ModSecurity",
    model: str = DEFAULT_MODEL,
) -> RefinementResult:
    if not new_rules:
        return RefinementResult(success=False, error_message="No rules provided for refinement")

    response_schema = {
        "type": "object",
        "properties": {
            "refined_rules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "rule": {"type": "string"},
                        "instructions": {"type": "string"},
                        "changes_made": {"type": "string"},
                    },
                    "required": ["rule", "instructions", "changes_made"],
                },
            },
            "removed_rules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "original_rule": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                    "required": ["original_rule", "reason"],
                },
            },
            "comparison_notes": {"type": "string"},
            "coverage_analysis": {"type": "string"},
        },
        "required": ["refined_rules", "removed_rules", "comparison_notes", "coverage_analysis"],
    }
    user_prompt = REFINEMENT_PROMPT_TEMPLATE.format(
        waf_type=waf_type,
        bypassed_payloads=json.dumps(bypassed_payloads[:10], indent=2),
        new_rules=json.dumps(new_rules, indent=2),
        existing_rules=json.dumps(existing_rules or [], indent=2),
    )

    error_message = None
    for attempt in range(5):
        try:
            response = claude_completion(
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                model=model,
                response_format={
                    "type": "json_schema",
                    "json_schema": {"name": "RuleRefinement", "schema": response_schema},
                },
            )
            content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
            try:
                result_json = json.loads(content)
            except json.JSONDecodeError as exc:
                pass
            
            refined_rules = result_json.get("refined_rules")
            if not refined_rules:
                
                
            return RefinementResult(
                success=True,
                refined_rules=refined_rules,
                removed_duplicates=len(result_json.get("removed_rules", [])),
                improvements_made=[
                    rule["changes_made"]
                    for rule in refined_rules
                    if rule.get("changes_made")
                ],
                comparison_notes=result_json.get("comparison_notes", ""),
            )
        except json.JSONDecodeError as exc:
            error_message = f"JSON parsing error: {exc}"
            return RefinementResult(
                success=False,
                refined_rules=new_rules,
                error_message=f"Failed to parse Claude response: {exc}",
            )
        except Exception as exc:
            if "503" in str(exc) and attempt < 4:
                continue
            return RefinementResult(
                success=False,
                refined_rules=new_rules,
                error_message=f"Rule refinement failed: {exc}",
            )

    return RefinementResult(
        success=False,
        refined_rules=new_rules,
        error_message="Rule refinement failed after retries",
    )
