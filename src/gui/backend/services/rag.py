from typing import Dict, Any

from ..services_external.rag import rag_retrieve

def enhance_defense_generation(
        attack_type: str,
        waf_name: str,
        bypassed_payloads: list,
        base_user_prompt: str,
        filter_rules_only: bool = True,
    ) -> Dict[str, Any]:
    
    # Call RAG service
    rag_result = rag_retrieve(
        attack_type=attack_type,
        waf_name=waf_name,
        bypassed_payloads=bypassed_payloads,
        initial_k=10,
        final_k=4,
        filter_rules_only=filter_rules_only
    )
    sources = rag_result.get("sources", [])
    if len(sources) <= 0:
        enhanced_prompt = base_user_prompt
    else:
        context = "\n\n".join([f"[Reference #{i + 1} : {source['source']}]{source['content']}" for i, source in enumerate(sources)])
        enhanced_prompt = f"""{base_user_prompt}

---
**KNOWLEDGE BASE REFERENCES**

The following references from our security knowledge base may help inform your defense strategy:

{context}

---

Please consider these references when generating defense rules, but prioritize the specific bypassed payloads mentioned above.
"""

    result = {"enhanced_prompt": enhanced_prompt}
    result.update(rag_result)
    return result