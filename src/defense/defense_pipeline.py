"""
Defense Rule Generation Pipeline.

Complete pipeline for generating WAF defense rules from bypassed payloads.

Pipeline Flow:
    [1] Bypassed Payloads -> Clustering (group similar payloads)
    [2] LLM (GPT-4) + RAG -> Generate initial rules
    [3] Syntax Validator -> Validate rule syntax
    [4] Gemini Agent -> Refine, dedupe, compare with existing rules
    [5] Output -> Final production-ready rules

Usage:
    from src.defense import DefensePipeline

    pipeline = DefensePipeline()
    result = pipeline.generate_defense_rules(
        bypassed_payloads=[...],
        waf_type="ModSecurity"
    )
"""

import json
import os
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

# Import validators
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validator_syntax_rule import (
    SyntaxValidator,
    WAFType,
    ValidationResult,
)

from .gemini_agent import GeminiRuleAgent, RefinementResult


class PipelineStage(Enum):
    """Pipeline stages for tracking progress."""
    CLUSTERING = "clustering"
    LLM_GENERATION = "llm_generation"
    SYNTAX_VALIDATION = "syntax_validation"
    GEMINI_REFINEMENT = "gemini_refinement"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class ClusterInfo:
    """Information about a payload cluster."""
    cluster_id: int
    payloads: list[str]
    attack_type: str
    representative_payload: str
    size: int


@dataclass
class GeneratedRule:
    """A generated WAF rule with metadata."""
    rule: str
    instructions: str
    waf_type: WAFType
    is_valid: bool = True
    validation_error: Optional[str] = None
    validation_warnings: Optional[list[str]] = None
    source_cluster: Optional[int] = None
    refinement_notes: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "instructions": self.instructions,
            "waf_type": self.waf_type.value,
            "is_valid": self.is_valid,
            "validation_error": self.validation_error,
            "validation_warnings": self.validation_warnings,
            "refinement_notes": self.refinement_notes,
        }


@dataclass
class PipelineResult:
    """Result of the defense pipeline execution."""
    success: bool
    stage: PipelineStage
    final_rules: list[GeneratedRule] = field(default_factory=list)
    # Metadata
    total_payloads: int = 0
    num_clusters: int = 0
    rules_generated: int = 0
    rules_valid: int = 0
    rules_invalid: int = 0
    rules_refined: int = 0
    duplicates_removed: int = 0
    # Debug info
    cluster_info: list[ClusterInfo] = field(default_factory=list)
    validation_errors: list[str] = field(default_factory=list)
    rag_sources: list[dict] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "stage": self.stage.value,
            "final_rules": [r.to_dict() for r in self.final_rules],
            "stats": {
                "total_payloads": self.total_payloads,
                "num_clusters": self.num_clusters,
                "rules_generated": self.rules_generated,
                "rules_valid": self.rules_valid,
                "rules_invalid": self.rules_invalid,
                "rules_refined": self.rules_refined,
                "duplicates_removed": self.duplicates_removed,
            },
            "rag_sources": self.rag_sources,
            "error_message": self.error_message,
        }


class DefensePipeline:
    """
    Complete defense rule generation pipeline.

    Orchestrates the flow from bypassed payloads to final WAF rules.
    """

    def __init__(
        self,
        openai_api_key: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        docs_folder: str = "./docs/",
        enable_rag: bool = True,
        enable_gemini: bool = True,
        enable_clustering: bool = True,
        max_retries: int = 3,
    ):
        """
        Initialize the defense pipeline.

        Args:
            openai_api_key: OpenAI API key (or set OPENAI_API_KEY env var)
            gemini_api_key: Google AI API key (or set GOOGLE_API_KEY env var)
            docs_folder: Path to RAG documents folder
            enable_rag: Enable RAG context enhancement
            enable_gemini: Enable Gemini refinement agent
            enable_clustering: Enable payload clustering
            max_retries: Max retries for LLM generation on syntax errors
        """
        self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
        self.docs_folder = docs_folder
        self.enable_rag = enable_rag
        self.enable_gemini = enable_gemini
        self.enable_clustering = enable_clustering
        self.max_retries = max_retries

        # Initialize components
        self.syntax_validator = SyntaxValidator()
        self.gemini_agent = GeminiRuleAgent(api_key=gemini_api_key) if enable_gemini else None

    def generate_defense_rules(
        self,
        bypassed_payloads: list[str],
        waf_info: Optional[dict] = None,
        waf_type: WAFType = WAFType.MODSECURITY,
        existing_rules: Optional[list[str]] = None,
        num_rules: int = 5,
        attack_type: Optional[str] = None,
    ) -> PipelineResult:
        """
        Generate defense rules from bypassed payloads.

        Args:
            bypassed_payloads: List of payloads that bypassed the WAF
            waf_info: WAF information dict
            waf_type: Target WAF type for generated rules
            existing_rules: Existing rules to avoid duplicates
            num_rules: Number of rules to generate
            attack_type: Type of attack (auto-detected if not provided)

        Returns:
            PipelineResult with generated rules and metadata
        """
        result = PipelineResult(
            success=False,
            stage=PipelineStage.CLUSTERING,
            total_payloads=len(bypassed_payloads),
        )

        if not bypassed_payloads:
            result.error_message = "No bypassed payloads provided"
            result.stage = PipelineStage.FAILED
            return result

        try:
            # Stage 1: Clustering
            print("[1/4] Clustering payloads...")
            clusters = self._cluster_payloads(bypassed_payloads)
            result.cluster_info = clusters
            result.num_clusters = len(clusters)
            print(f"      Created {len(clusters)} clusters")

            # Stage 2: LLM Generation
            result.stage = PipelineStage.LLM_GENERATION
            print("[2/4] Generating rules with LLM + RAG...")

            # Auto-detect attack type
            if not attack_type:
                attack_type = self._detect_attack_type(bypassed_payloads)

            generated_rules = self._generate_rules_with_llm(
                payloads=bypassed_payloads,
                clusters=clusters,
                waf_info=waf_info or {},
                waf_type=waf_type,
                num_rules=num_rules,
                attack_type=attack_type,
            )
            result.rules_generated = len(generated_rules)
            print(f"      Generated {len(generated_rules)} rules")

            # Stage 3: Syntax Validation
            result.stage = PipelineStage.SYNTAX_VALIDATION
            print("[3/4] Validating rule syntax...")

            valid_rules, invalid_rules = self._validate_rules(generated_rules, waf_type)
            result.rules_valid = len(valid_rules)
            result.rules_invalid = len(invalid_rules)
            result.validation_errors = [r.validation_error for r in invalid_rules if r.validation_error]
            print(f"      Valid: {len(valid_rules)}, Invalid: {len(invalid_rules)}")

            # Retry invalid rules
            if invalid_rules and self.max_retries > 0:
                print(f"      Retrying {len(invalid_rules)} invalid rules...")
                retry_rules = self._retry_invalid_rules(
                    invalid_rules, waf_type, bypassed_payloads, attack_type
                )
                valid_rules.extend(retry_rules)
                result.rules_valid = len(valid_rules)

            # Stage 4: Gemini Refinement
            result.stage = PipelineStage.GEMINI_REFINEMENT
            if self.enable_gemini and self.gemini_agent and self.gemini_agent.available:
                print("[4/4] Refining rules with Gemini agent...")

                refinement_result = self.gemini_agent.refine_rules(
                    new_rules=[{"rule": r.rule, "instructions": r.instructions} for r in valid_rules],
                    bypassed_payloads=bypassed_payloads,
                    existing_rules=[{"rule": r} for r in (existing_rules or [])],
                    waf_type=waf_type.value,
                )

                if refinement_result.success:
                    # Update rules with refined versions
                    refined_rules = []
                    for refined in refinement_result.refined_rules:
                        refined_rules.append(GeneratedRule(
                            rule=refined.get("rule", ""),
                            instructions=refined.get("instructions", ""),
                            waf_type=waf_type,
                            is_valid=True,
                            refinement_notes=refined.get("changes_made"),
                        ))
                    valid_rules = refined_rules
                    result.rules_refined = len(refined_rules)
                    result.duplicates_removed = refinement_result.removed_duplicates
                    print(f"      Refined {len(refined_rules)} rules, removed {result.duplicates_removed} duplicates")
                else:
                    print(f"      Refinement failed: {refinement_result.error_message}")
            else:
                print("[4/4] Skipping Gemini refinement (disabled or unavailable)")

            # Final result
            result.final_rules = valid_rules
            result.stage = PipelineStage.COMPLETE
            result.success = len(valid_rules) > 0

            print(f"\nPipeline complete! Generated {len(valid_rules)} valid rules.")
            return result

        except Exception as e:
            result.error_message = str(e)
            result.stage = PipelineStage.FAILED
            print(f"\nPipeline failed: {e}")
            return result

    def _cluster_payloads(self, payloads: list[str]) -> list[ClusterInfo]:
        """Cluster similar payloads together."""
        if not self.enable_clustering or len(payloads) < 3:
            # Return single cluster with all payloads
            attack_type = self._detect_attack_type(payloads)
            return [ClusterInfo(
                cluster_id=0,
                payloads=payloads,
                attack_type=attack_type,
                representative_payload=payloads[0],
                size=len(payloads),
            )]

        try:
            # Import clustering service — support both run contexts
            try:
                from services.clustering import clustering
            except ImportError:
                from gui.backend.services.clustering import clustering

            labels = clustering(payloads, reduce_dim_to=50, method="HAC", cluster_kwargs={"distance_threshold": 1.5})

            # Group by cluster
            from collections import defaultdict
            clusters_dict = defaultdict(list)
            for payload, label in zip(payloads, labels):
                clusters_dict[label].append(payload)

            clusters = []
            for label, cluster_payloads in clusters_dict.items():
                if label == -1:  # Noise
                    continue
                attack_type = self._detect_attack_type(cluster_payloads)
                clusters.append(ClusterInfo(
                    cluster_id=label,
                    payloads=cluster_payloads,
                    attack_type=attack_type,
                    representative_payload=cluster_payloads[0],
                    size=len(cluster_payloads),
                ))

            return clusters if clusters else [ClusterInfo(
                cluster_id=0,
                payloads=payloads,
                attack_type=self._detect_attack_type(payloads),
                representative_payload=payloads[0],
                size=len(payloads),
            )]

        except Exception as e:
            print(f"      Clustering failed: {e}, using single cluster")
            return [ClusterInfo(
                cluster_id=0,
                payloads=payloads,
                attack_type=self._detect_attack_type(payloads),
                representative_payload=payloads[0],
                size=len(payloads),
            )]

    def _generate_rules_with_llm(
        self,
        payloads: list[str],
        clusters: list[ClusterInfo],
        waf_info: dict,
        waf_type: WAFType,
        num_rules: int,
        attack_type: str,
    ) -> list[GeneratedRule]:
        """Generate rules using LLM with RAG enhancement."""
        try:
            # Import LLM service — support both run contexts:
            # (a) python app.py  from src/gui/backend/   → absolute imports work
            # (b) python -m src.xxx                      → relative imports work
            try:
                from services_external.llm import chatgpt_completion
                from config.prompts import BLUE_TEAM_SYSTEM_PROMPT, get_blue_team_user_prompt
            except ImportError:
                from gui.backend.services_external.llm import chatgpt_completion
                from gui.backend.config.prompts import BLUE_TEAM_SYSTEM_PROMPT, get_blue_team_user_prompt

            # Build prompt
            base_prompt = get_blue_team_user_prompt(
                waf_info=json.dumps(waf_info),
                bypassed_payloads=json.dumps(payloads[:20]),  # Limit for token efficiency
                bypassed_instructions=json.dumps([f"Payload from cluster {c.cluster_id}" for c in clusters]),
                num_rules=num_rules,
            )

            # Enhance with RAG if enabled
            if self.enable_rag:
                try:
                    try:
                        from RAG.rag_service import enhance_defense_generation
                    except ImportError:
                        from gui.backend.RAG.rag_service import enhance_defense_generation

                    rag_result = enhance_defense_generation(
                        waf_info=waf_info,
                        bypassed_payloads=payloads,
                        bypassed_instructions=[],
                        base_user_prompt=base_prompt,
                        docs_folder=self.docs_folder,
                        enable_rag=True,
                    )
                    user_prompt = rag_result["enhanced_prompt"]
                except Exception as e:
                    print(f"      RAG enhancement failed: {e}, using base prompt")
                    user_prompt = base_prompt
            else:
                user_prompt = base_prompt

            # Add WAF type instruction
            waf_format_instruction = self._get_waf_format_instruction(waf_type)
            user_prompt += f"\n\n{waf_format_instruction}"

            # Call LLM
            messages = [
                {"role": "system", "content": BLUE_TEAM_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]

            response_format = {
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
                                }
                            }
                        },
                        "required": ["items"]
                    }
                },
            }

            result = chatgpt_completion(messages=messages, response_format=response_format)

            # Parse response — chatgpt_completion returns raw OpenAI JSON:
            # {"choices": [{"message": {"content": "{...}"}}], ...}
            content_str = (
                result.get("choices", [{}])[0]
                      .get("message", {})
                      .get("content")
            )
            if not content_str:
                print(f"      LLM returned empty content. Full response: {result}")
                return []

            content = json.loads(content_str)
            rules = []
            for item in content.get("items", []):
                rules.append(GeneratedRule(
                    rule=item.get("rule", ""),
                    instructions=item.get("instructions", ""),
                    waf_type=waf_type,
                ))
            return rules

        except Exception as e:
            print(f"      LLM generation failed: {e}")
            return []

    def _validate_rules(
        self,
        rules: list[GeneratedRule],
        waf_type: WAFType,
    ) -> tuple[list[GeneratedRule], list[GeneratedRule]]:
        """Validate rule syntax and separate valid/invalid."""
        valid_rules = []
        invalid_rules = []

        for rule in rules:
            if not rule.rule.strip():
                rule.is_valid = False
                rule.validation_error = "Empty rule"
                invalid_rules.append(rule)
                continue

            result = self.syntax_validator.validate(rule.rule, waf_type)
            rule.is_valid = result.is_valid
            rule.validation_error = result.error_message
            rule.validation_warnings = result.warnings

            if result.is_valid:
                valid_rules.append(rule)
            else:
                invalid_rules.append(rule)

        return valid_rules, invalid_rules

    def _retry_invalid_rules(
        self,
        invalid_rules: list[GeneratedRule],
        waf_type: WAFType,
        payloads: list[str],
        attack_type: str,
    ) -> list[GeneratedRule]:
        """Retry generating rules that failed validation."""
        fixed_rules = []

        try:
            try:
                from services_external.llm import chatgpt_completion
            except ImportError:
                from gui.backend.services_external.llm import chatgpt_completion

            for rule in invalid_rules[:self.max_retries]:  # Limit retries
                fix_prompt = f"""The following WAF rule has a syntax error:

Rule: {rule.rule}
Error: {rule.validation_error}

Please fix the syntax error and return a valid {waf_type.value} rule.
The rule should block payloads like: {payloads[0] if payloads else 'XSS/SQL injection attacks'}

Return ONLY the fixed rule, no explanations."""

                result = chatgpt_completion(
                    messages=[{"role": "user", "content": fix_prompt}]
                )

                fixed_content = (
                    result.get("choices", [{}])[0]
                        .get("message", {})
                        .get("content", "")
                )
                if fixed_content:
                    fixed_rule = GeneratedRule(
                        rule=fixed_content.strip(),
                        instructions=rule.instructions,
                        waf_type=waf_type,
                    )

                    # Validate fixed rule
                    validation = self.syntax_validator.validate(fixed_rule.rule, waf_type)
                    if validation.is_valid:
                        fixed_rule.is_valid = True
                        fixed_rules.append(fixed_rule)

        except Exception as e:
            print(f"      Retry failed: {e}")

        return fixed_rules

    def _get_waf_format_instruction(self, waf_type: WAFType) -> str:
        """Get format instruction for specific WAF type."""
        instructions = {
            WAFType.MODSECURITY: """
**OUTPUT FORMAT**: Generate rules in ModSecurity SecRule format:
SecRule VARIABLES "OPERATOR" "id:XXXXX,phase:2,deny,status:403,msg:'Description',t:urlDecode,t:lowercase"

Required:
- Unique rule ID (start from 900001)
- Phase (usually 2 for request body)
- Transformations (t:urlDecode, t:lowercase, t:htmlEntityDecode)""",

            WAFType.CLOUDFLARE: """
**OUTPUT FORMAT**: Generate rules in Cloudflare expression syntax:
(http.request.uri contains "pattern" or http.request.body contains "pattern")

Use Cloudflare fields: http.request.uri, http.request.body, http.request.headers, etc.""",

            WAFType.AWS_WAF: """
**OUTPUT FORMAT**: Generate rules in AWS WAF JSON format:
{
    "ByteMatchStatement": {
        "SearchString": "pattern",
        "FieldToMatch": {"UriPath": {}},
        "TextTransformations": [{"Priority": 0, "Type": "URL_DECODE"}],
        "PositionalConstraint": "CONTAINS"
    }
}""",

            WAFType.NAXSI: """
**OUTPUT FORMAT**: Generate rules in Naxsi format:
MainRule "rx:pattern" "msg:Description" "mz:BODY|URL|ARGS" "s:$XSS:8" id:XXXXX;

Required:
- Pattern (rx: for regex, str: for string match)
- Match zone (mz:)
- Score (s:$VAR:N)
- Unique ID""",
        }

        return instructions.get(waf_type, "Generate rules in appropriate WAF format.")

    def _detect_attack_type(self, payloads: list[str]) -> str:
        """Detect attack type from payloads."""
        payload_str = " ".join(str(p) for p in payloads).lower()

        xss_keywords = ["script", "onerror", "onload", "alert", "img", "svg", "iframe", "javascript"]
        sql_keywords = ["union", "select", "insert", "update", "delete", "drop", "or 1=1", "' or", "and 1=1"]

        xss_count = sum(1 for k in xss_keywords if k in payload_str)
        sql_count = sum(1 for k in sql_keywords if k in payload_str)

        if xss_count > sql_count:
            return "XSS"
        elif sql_count > xss_count:
            return "SQLI"
        else:
            return "Unknown"


# Convenience function
def generate_defense_rules(
    bypassed_payloads: list[str],
    waf_type: str = "modsecurity",
    existing_rules: Optional[list[str]] = None,
    num_rules: int = 5,
    enable_rag: bool = True,
    enable_gemini: bool = True,
) -> PipelineResult:
    """
    Convenience function to generate defense rules.

    Args:
        bypassed_payloads: List of payloads that bypassed the WAF
        waf_type: Target WAF type (modsecurity, cloudflare, aws_waf, naxsi)
        existing_rules: Existing rules to avoid duplicates
        num_rules: Number of rules to generate
        enable_rag: Enable RAG context enhancement
        enable_gemini: Enable Gemini refinement

    Returns:
        PipelineResult with generated rules
    """
    waf_type_enum = WAFType(waf_type.lower())

    pipeline = DefensePipeline(
        enable_rag=enable_rag,
        enable_gemini=enable_gemini,
    )

    return pipeline.generate_defense_rules(
        bypassed_payloads=bypassed_payloads,
        waf_type=waf_type_enum,
        existing_rules=existing_rules,
        num_rules=num_rules,
    )
