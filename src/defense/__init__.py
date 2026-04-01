"""
Defense Rule Generation Module.

Complete pipeline for generating WAF defense rules from bypassed payloads.

Pipeline Flow:
    [1] Bypassed Payloads -> Clustering (group similar payloads)
    [2] LLM (GPT-4) + RAG -> Generate initial rules
    [3] Syntax Validator -> Validate rule syntax (ModSecurity, Cloudflare, AWS WAF, Naxsi)
    [4] Gemini Agent -> Refine, dedupe, compare with existing rules
    [5] Output -> Final production-ready rules

Usage:
    from src.defense import DefensePipeline, generate_defense_rules

    # Quick usage
    result = generate_defense_rules(
        bypassed_payloads=["<script>alert(1)</script>", "' OR 1=1 --"],
        waf_type="modsecurity",
        num_rules=5
    )

    # Full control
    pipeline = DefensePipeline(
        enable_rag=True,
        enable_gemini=True,
        enable_clustering=True
    )
    result = pipeline.generate_defense_rules(
        bypassed_payloads=[...],
        waf_type=WAFType.MODSECURITY,
        existing_rules=[...],
        num_rules=5
    )

    # Access results
    if result.success:
        for rule in result.final_rules:
            print(f"Rule: {rule.rule}")
            print(f"Instructions: {rule.instructions}")
"""

from .defense_pipeline import (
    DefensePipeline,
    PipelineResult,
    PipelineStage,
    GeneratedRule,
    ClusterInfo,
    generate_defense_rules,
)

from .gemini_agent import (
    GeminiRuleAgent,
    RefinementResult,
    get_gemini_agent,
)

# Re-export WAFType for convenience
try:
    # When src/ is in sys.path (absolute import)
    from validator_syntax_rule import WAFType
except ImportError:
    # When imported as part of src package (relative import)
    from ..validator_syntax_rule import WAFType


__all__ = [
    # Main pipeline
    "DefensePipeline",
    "generate_defense_rules",
    # Result classes
    "PipelineResult",
    "PipelineStage",
    "GeneratedRule",
    "ClusterInfo",
    # Gemini agent
    "GeminiRuleAgent",
    "RefinementResult",
    "get_gemini_agent",
    # WAF type
    "WAFType",
]

__version__ = "1.0.0"
