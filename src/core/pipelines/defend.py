
import json
from collections import defaultdict
from typing import Any, Optional

from prompts import (
    BLUE_TEAM_SYSTEM_PROMPT,
    build_refine_enhance_rules_prompt,
    build_refine_sync_rules_prompt,
    build_refine_system_prompt,
    get_blue_team_user_prompt,
    build_fix_rule_prompt,
)
from services.clustering import clustering
from external_services.llm_api import chatgpt_completion, claude_completion
from external_services.llmshield import rag_retrieve
from services.rule_syntax_validator import validator
from dtos import PayloadResult

def _parse_existing_rules(rules_raw: Optional[list[str]]) -> list[str]:
    extracted_rules: list[str] = []
    if not rules_raw or not isinstance(rules_raw, list):
        return extracted_rules

    for rules in rules_raw:
        try:
            rules_json = json.loads(rules)
            if not isinstance(rules_json, list):
                continue
            for item in rules_json:
                if isinstance(item, dict):
                    rule = item.get("rule")
                    if isinstance(rule, str) and rule.strip():
                        extracted_rules.append(rule.strip())
                elif isinstance(item, str) and item.strip():
                    extracted_rules.append(item.strip())
        except json.JSONDecodeError:
            lines = [
                line for line in str(rules).split("\n")
                if line.strip() and not line.strip().startswith("#")
            ]
            content = "\n".join(lines).replace("\\\n", " ").replace("\\\r\n", " ")
            extracted_rules.extend([line.strip() for line in content.split("\n") if line.strip()])

    return extracted_rules


def _1_clustering(
    bypassed_payloads: list[PayloadResult],
    attack_type: str,
) -> list[dict[str, Any]]:
    if len(bypassed_payloads) < 3:
        labels = [0] * len(bypassed_payloads)
    else:
        labels = clustering(
            bypassed_payloads,
            reduce_dim_to=50,
            method="HAC",
            cluster_kwargs={"distance_threshold": 1.5},
        )

    grouped: defaultdict[int, list[str]] = defaultdict(list)
    for payload, label in zip(bypassed_payloads, labels):
        grouped[int(label)].append(payload)

    print(f"[CLUSTERING] Formed {len(grouped)} clusters from {len(bypassed_payloads)} payloads")
    clusters = []
    for label, cluster_payloads in grouped.items():
        if label == -1:
            continue
        print(f"\tCluster {label} -> {len(cluster_payloads)} payloads")
        for p in cluster_payloads:
            print(f"\t\t{p}")
        clusters.append({
            "cluster_id": int(label),
            "payloads": cluster_payloads,
            "attack_type": attack_type,
            "representative_payload": cluster_payloads[0],
            "size": len(cluster_payloads),
        })

    return clusters


def _2_rag_retrieve(
    waf_name: str,
    attack_type: str,
    bypassed_payloads: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    rag_result = rag_retrieve(
        attack_type=attack_type,
        waf_name=waf_name,
        bypassed_payloads=bypassed_payloads,
        initial_k=10,
        final_k=4,
        filter_rules_only=True,
    )
    print(f"[RAG] Queries :")
    for query in rag_result.get("queries", []):
        print(f"\t{query}")

    print(f"[RAG] Sources :")
    for source in rag_result.get("sources", []):
        print(f"\t[{source['source']}]")
        print(f"\t\t[{source['content'].replace('\n', '\n\t\t')}]")

    rag_sources = rag_result["sources"]
    rag_context = rag_result["context"]
    return rag_result, rag_sources, rag_context


def _3_generate_rules(
    waf_name: str,
    clusters: list[dict[str, Any]],
    rag_context: str,
) -> tuple[list[dict[str, str]], str]:
    base_prompt = get_blue_team_user_prompt(
        waf_name=waf_name,
        payload_clusters=clusters,
    )

    prompt = f"""{base_prompt}

---
**KNOWLEDGE BASE REFERENCES FOR RULE GENERATION**

{rag_context}

---
Use the references above as implementation evidence for writing WAF rules.
Prioritize WAF-specific syntax, fields, operators, transformations, actions, and concrete examples.
Ignore references that only describe the attack generally but do not help write a rule.
Prioritize the specific bypassed payloads mentioned above.
"""

    response = chatgpt_completion(
        messages=[
            {"role": "system", "content": BLUE_TEAM_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        model="gpt-5.4",
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "DefenseRuleList",
                "schema": {
                    "type": "object",
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "rule": {"type": "string"},
                                    "instructions": {"type": "string"},
                                },
                                "required": ["rule", "instructions"],
                            },
                        }
                    },
                    "required": ["items"],
                },
            },
        },
    )

    content = response["choices"][0]["message"]["content"]

    parsed = json.loads(content)
    generated_rules = [
        {
            "rule": item.get("rule", "").strip(),
            "instructions": item.get("instructions", "").strip(),
        }
        for item in parsed.get("items", [])
        if item.get("rule")
    ]
    print(f"[GENERATE-RULES] Generated {len(generated_rules)} rules")
    for i, rule in enumerate(generated_rules):
        print(f"\tRule #{i + 1}: {rule['rule']}")
        if rule.get("instructions"):
            print(f"\t\tInstructions: {rule['instructions']}")
    return generated_rules, prompt


def _4_validate_rules_syntax(
    generated_rules: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    valid_rules = []
    invalid_rules = []
    for rule in generated_rules:
        validation = validator.validate(rule.get("rule", ""))
        enriched_rule = {
            **rule,
            "is_valid": validation.is_valid,
            "validation_error": validation.error_message,
            "validation_warnings": validation.warnings or [],
        }
        if validation.is_valid:
            valid_rules.append(enriched_rule)
        else:
            invalid_rules.append(enriched_rule)

    print(f"[VALIDATION] {len(valid_rules)} valid rules, {len(invalid_rules)} invalid rules")
    for i, rule in enumerate(invalid_rules):
        print(f"\tInvalid Rule #{i + 1}: {rule['rule']}")
        print(f"\t\tError: {rule['validation_error']}")
        if rule.get("validation_warnings"):
            print(f"\t\tWarnings: {rule['validation_warnings']}")
    return valid_rules, invalid_rules


def _5_retry_invalid_rules(
    waf_name: str,
    invalid_rules: list[dict],
) -> list[dict]:
    retried_rules = []
    for rule in invalid_rules:
        fix_prompt = build_fix_rule_prompt(
            waf_name=waf_name,
            rule=rule,
        )

        response = chatgpt_completion(
            model="gpt-5.4",
            messages=[{"role": "user", "content": fix_prompt}],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "FixedRule",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "rule": {"type": "string"},
                            "instructions": {"type": "string"},
                        },
                        "required": ["rule", "instructions"],
                    },
                },
            },
        )
        content = response["choices"][0]["message"]["content"]
        fixed_rule = json.loads(content)

        normalized_rule = {
            "rule": fixed_rule.get("rule", "").strip(),
            "instructions": fixed_rule.get("instructions", rule.get("instructions", "")).strip(),
        }
        validation = validator.validate(normalized_rule["rule"])
        if validation.is_valid:
            normalized_rule["is_valid"] = True
            normalized_rule["validation_error"] = None
            normalized_rule["validation_warnings"] = validation.warnings or []
            retried_rules.append(normalized_rule)

    print(f"[RETRY] Retried {len(retried_rules)} rules")
    for i, rule in enumerate(retried_rules):
        print(f"\tRetried Rule #{i + 1}: {rule['rule']}")
        if rule.get("instructions"):
            print(f"\t\tInstructions: {rule['instructions']}")
        if rule.get("validation_warnings"):
            print(f"\t\tWarnings: {rule['validation_warnings']}")


    return retried_rules


def _6_refine_rules(
    waf_name: str,
    valid_rules: list[dict[str, Any]],
    existing_rules: list[str]|None = None,
) -> list[dict[str, Any]]:
    candidate_rules = [
        {"rule": rule["rule"], "instructions": rule.get("instructions", "")}
        for rule in valid_rules
        if rule.get("rule")
    ]
    user_prompt = build_refine_sync_rules_prompt(
        waf_name=waf_name,
        existing_rules="\t" + "\n\t".join(rule for rule in existing_rules or []),
        new_rules="\t" + "\n\t".join(rule["rule"] for rule in candidate_rules),
    ) if existing_rules else build_refine_enhance_rules_prompt(
        waf_name=waf_name,
        new_rules="\t" + "\n\t".join(rule["rule"] for rule in candidate_rules),
    )

    last_error: Exception | None = None
    for attempt in range(5):
        try:
            response = claude_completion(
                messages=[
                    {"role": "system", "content": build_refine_system_prompt()},
                    {"role": "user", "content": user_prompt},
                ],
                model="claude-sonnet-4-6",
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "RuleRefinement",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "refined_rules": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "rule": {"type": "string"},
                                            "instructions": {"type": "string"},
                                        },
                                        "required": ["rule", "instructions"],
                                    },
                                },
                                "comparison_notes": {"type": "string"},
                                "coverage_analysis": {"type": "string"},
                            },
                            "required": ["refined_rules", "comparison_notes", "coverage_analysis"],
                        },
                    },
                },
            )

            refined_rules = json.loads(response["choices"][0]["message"]["content"])["refined_rules"]
            if isinstance(refined_rules, list):
                return refined_rules
            last_error = ValueError("refined_rules must be a list")
        except Exception as exc:
            last_error = exc
            print(f"[REFINE-RULES] #{attempt + 1}/5 failed: {exc}")

    raise last_error or RuntimeError("Refine rules failed")


