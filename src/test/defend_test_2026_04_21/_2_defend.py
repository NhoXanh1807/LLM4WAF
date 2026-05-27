

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "core")))
import json
sys.stdout.reconfigure(encoding='utf-8')
from defend_pipeline import (
    _1_clustering,
    _2_rag_retrieve,
    _3_generate_rules,
    _4_validate_rules_syntax,
    _5_retry_invalid_rules,
    _6_refine_rules,
)
from models.dtos import PayloadResult
sys.path.append(os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    ".."
)))
from utils import WAF_DVWA_URLS


def _parse_payload_results(items: list[dict]) -> list[PayloadResult]:
    return [
        PayloadResult(
            payload=item.get("payload", ""),
            technique=item.get("technique", ""),
            attack_type=item.get("attack_type", ""),
            status_code=item.get("status_code"),
            is_bypassed=item.get("is_bypassed"),
            is_harmful=item.get("is_harmful"),
        )
        for item in items
        if isinstance(item, dict)
    ]


def _extract_bypassed_payloads(payload_results: list[PayloadResult]) -> list[str]:
    return [
        str(item.payload).strip()
        for item in payload_results
        if (
            item.is_bypassed 
            and item.is_harmful 
            and str(item.payload).strip())
    ]

def _run_defend_pipeline(
    waf_name: str,
    attack_type: str,
    payload_results: list[dict],
    existing_rules: list[str] | None,
    enable_clustering: bool = True,
    enable_rag: bool = True,
    enable_validate_retry: bool = True,
    enable_refine: bool = True,
) -> dict:
    parsed_payload_results = _parse_payload_results(payload_results)
    bypassed_payloads = _extract_bypassed_payloads(parsed_payload_results)
    
    if not bypassed_payloads:
        raise ValueError(f"No bypassed harmful payloads found for waf={waf_name}, attack_type={attack_type}")

    if enable_clustering:
        clusters = _1_clustering(bypassed_payloads=bypassed_payloads)
    else:
        clusters = [{
            "cluster_id": "Clustering disabled, this is a flat list of payloads",
            "size": len(bypassed_payloads), 
            "payloads": bypassed_payloads
        }]
    
    if enable_rag:
        rag_result, rag_sources, rag_context = _2_rag_retrieve(
            waf_name=waf_name,
            attack_type=attack_type,
            bypassed_payloads=bypassed_payloads,
        )
    else:
        rag_result = ""
        rag_sources = []
        rag_context = ""
    
    generated_rules, generation_prompt = _3_generate_rules(
        waf_name=waf_name,
        clusters=clusters,
        rag_context=rag_context,
    )
    
    if enable_validate_retry:
        valid_rules, invalid_rules = _4_validate_rules_syntax(generated_rules)
        fixed_rules = _5_retry_invalid_rules(
            waf_name=waf_name,
            invalid_rules=invalid_rules,
        ) if invalid_rules else []
    else:
        valid_rules = generated_rules
        invalid_rules = []
        fixed_rules = []
    
    if enable_refine:
        final_rules = _6_refine_rules(
            waf_name=waf_name,
            valid_rules=[*valid_rules, *fixed_rules],
            existing_rules=existing_rules,
        )
    else:
        final_rules = [*valid_rules, *fixed_rules]

    return {
        "success": True,
        "data": {
            "waf_name": waf_name,
            "existing_rules_count": len(existing_rules or []),
            "enabled_steps": {
                "clustering": enable_clustering,
                "rag": enable_rag,
                "validate_retry": enable_validate_retry,
                "refine": enable_refine,
            },
            "stats": {
                "total_payloads": len(parsed_payload_results),
                "num_bypassed_payloads": len(bypassed_payloads),
                "num_clusters": len(clusters),
                "rules_generated": len(generated_rules),
                "rules_valid": len(valid_rules),
                "rules_invalid": len(invalid_rules),
                "rules_fixed": len(fixed_rules),
                "rules_refined": len(final_rules),
            },
            "clustered_payloads": clusters,
            "rag_result": rag_result,
            "rag_sources": rag_sources,
            "rag_context": rag_context,
            "generation_prompt": generation_prompt,
            "generated_rules": generated_rules,
            "fixed_rules": fixed_rules,
            "final_rules": final_rules,
        },
    }


input_dir = os.path.join(os.path.dirname(__file__), '1_after_convert')
output_dir = os.path.join(os.path.dirname(__file__), '2_after_defend')

os.makedirs(output_dir, exist_ok=True)
    
with open(os.path.join(os.path.dirname(__file__), "existing_rules", "naxsi_core.rules"), "r", encoding="utf-8") as f:
    naxsi_rules = [line.strip() for line in f.readlines() if not line.startswith('#') and line.strip()]
with open(os.path.join(os.path.dirname(__file__), "existing_rules", "REQUEST-941-APPLICATION-ATTACK-XSS.conf"), "r", encoding="utf-8") as f:
    modsec_xss_rules = [line.strip() for line in f.readlines() if not line.startswith('#') and line.strip()]
with open(os.path.join(os.path.dirname(__file__), "existing_rules", "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"), "r", encoding="utf-8") as f:
    modsec_sqli_rules = [line.strip() for line in f.readlines() if not line.startswith('#') and line.strip()]

waf_attack_type_mapping = {
    "ModSecurity": "xss_stored",
    "Naxsi":"xss_dom",
    "Cloudflare":"sql_injection_blind",
    "AWS":"sql_injection",
}

for waf in WAF_DVWA_URLS:
    for exclude in [
        # 'clustering', 
        # 'rag_val_retry_refine', 
        'none'
    ]:
        attack_type = waf_attack_type_mapping.get(waf)
        phase = "PHASE_3" if waf != "Cloudflare" else "PHASE_1"
        file_name = f"result.{waf}.{attack_type}.{phase}.json"
        new_file_name = f"defend.exclude.{exclude}.{waf}.{attack_type}.{phase}.json"
        input_path = os.path.join(input_dir, file_name)
        output_path = os.path.join(output_dir, new_file_name)

        print(f"[{waf}|{attack_type}|{phase}] Loading {input_path}")
        with open(input_path, 'r', encoding='utf-8') as f:
            payload_results = json.load(f)

        print(f"[{waf}|{attack_type}|{phase}] Running local defend pipeline for waf={waf}, attack_type={attack_type}, phase={phase}")
        existing_rules = None
        if waf.lower() == "naxsi":
            existing_rules = naxsi_rules
        elif waf.lower() == "modsecurity":
            if "xss" in attack_type.lower():
                existing_rules = modsec_xss_rules
            elif "sql" in attack_type.lower():
                existing_rules = modsec_sqli_rules

        result = _run_defend_pipeline(
            waf_name=waf,
            payload_results=payload_results,
            existing_rules=existing_rules,
            attack_type=attack_type,
            enable_clustering=(exclude != 'clustering'),
            enable_rag=(exclude != 'rag_val_retry_refine'),
            enable_validate_retry=(exclude != 'rag_val_retry_refine'),
            enable_refine=(exclude != 'rag_val_retry_refine'),
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=4)

        print(f"[{waf}|{attack_type}|{phase}] Saved {output_path}")
