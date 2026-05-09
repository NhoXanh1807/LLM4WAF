
import requests
from dtos import PayloadResult
from settings import LLMSHIELD_ENDPOINT

def llmshield_build_prompt(waf_name: str, attack_type: str, technique: str, probe_history: list[PayloadResult]|None = None) -> str|None:
    data = {
        "waf_name": waf_name,
        "attack_type": attack_type,
        "technique": technique,
        "probe_history": [p.__dict__ for p in probe_history] if probe_history is not None else None
    }
    url = LLMSHIELD_ENDPOINT + "?action=" + "build_prompt"
    response = requests.post(url, json=data)
    return response.text


def llmshield_generate_response(prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase1") -> dict|None:
    data = {
        "max_new_tokens": max_new_tokens,
        "temperature": temperature,
        "adapter_name": adapter_name,
        "prompt": prompt,
    }
    url = LLMSHIELD_ENDPOINT + "?action=" + "generate"
    response = requests.post(url, json=data)
    return response.text

def llmshield_generate_payloads(waf_name: str, attack_type: str, techniques: str = None, probe_history: list[dict]|None = None, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase1") -> str|None:
    data = {
        "waf_name": waf_name,
        "attack_type": attack_type,
        "technique": techniques,
        "max_new_tokens": max_new_tokens,
        "temperature": temperature,
        "adapter_name": adapter_name,
        "probe_history": probe_history,
    }
    url = LLMSHIELD_ENDPOINT + "?action=" + "generate_payload"
    while True:
        try:
            response = requests.post(url, json=data)
            return response.text
        except Exception as e:
            continue


# _clean_attack_type() dùng có một lần thôi mà cũng chỉ đơn giản là strip()
# trong hệ thống cũng không có trường hợp attack_type = None nên cũng không cần _clean_attack_type()
# def _clean_attack_type(attack_type: Any) -> str:
#     if attack_type is None:
#         return ""
#     return str(attack_type).strip()


def rag_retrieve(
    attack_type: str,
    waf_name: str,
    bypassed_payloads: list|None = None,
    initial_k: int = 10,
    final_k: int = 4,
    filter_rules_only: bool = True,
) -> dict:
    """
    Call LLMShield RAG.

    This function assumes services.rag has already resolved attack_type. It still
    validates the value to prevent accidental retrieval queries with "unknown".
    """
    bypassed_payloads = bypassed_payloads or []
    # _clean_attack_type() dùng có một lần thôi mà cũng chỉ đơn giản là strip()
    # trong hệ thống cũng không có trường hợp attack_type = None nên cũng không cần _clean_attack_type()
    # resolved_attack_type = _clean_attack_type(attack_type)
    resolved_attack_type = attack_type.strip()

    # Theo flow hệ thống không có trường hợp nào gọi hàm rag_retrieve với attack_type lạ nên không cần validate
    # if resolved_attack_type.lower() in UNKNOWN_ATTACK_TYPES:
    #     return {
    #         "type": "error",
    #         "message": "Invalid attack_type for RAG. Refusing to call LLMShield with unknown attack_type.",
    #         "attack_type_input": attack_type,
    #         "sources": [],
    #         "queries": [],
    #         "rag_enabled": False,
    #     }

    data = {
        "attack_type": resolved_attack_type,
        "waf_name": waf_name,
        "bypassed_payloads": bypassed_payloads,
        "initial_k": int(initial_k),
        "final_k": int(final_k),
        "filter_rules_only": bool(filter_rules_only),
    }

    url = f"{LLMSHIELD_ENDPOINT}?action=rag_retrieve"

    try:
        print(f"[LLM4WAF -> LLMShield RAG] url={url}")
        print(f"[LLM4WAF -> LLMShield RAG] attack_type={resolved_attack_type!r}, waf_name={waf_name!r}")

        response = requests.post(url, json=data, timeout=90)
        response.raise_for_status()

        # Action rag_retrieve của LLMShield luôn trả về JSON
        # Không cần validate dư thừa, nếu có lỗi thì mình cần phải fix ở LLMShield
        # try:
        #     result = response.json()
        # except ValueError:
        #     return {
        #         "type": "error",
        #         "message": "LLMShield RAG returned non-JSON response.",
        #         "status_code": response.status_code,
        #         "raw_response": response.text[:1000],
        #         "sources": [],
        #         "queries": [],
        #     }
        result = response.json()

        # Không cần validate !!!
        # if not isinstance(result, dict):
        #     return {
        #         "type": "error",
        #         "message": f"LLMShield RAG returned {type(result).__name__}, expected dict.",
        #         "raw_response": result,
        #         "sources": [],
        #         "queries": [],
        #     }

        result.setdefault("attack_type_sent", resolved_attack_type)
        return result

    except Exception as e:
        print(f"Error in rag_retrieve: {str(e)}")
        return {
            "type": "error",
            "message": str(e),
            "attack_type_sent": resolved_attack_type,
            "sources": [],
            "queries": [],
        }
