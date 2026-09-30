
import json
import time
import requests
from models.dtos import PayloadResult
from config.settings import LLMSHIELD_ENDPOINT


def _validate_llmshield_response(response: requests.Response) -> None:
    """Raise if the response is not a real LLMShield payload response.

    A dead ngrok tunnel / offline GPU VM still returns HTTP 200 with an HTML
    error page (e.g. ERR_NGROK_3200), which would otherwise get silently
    saved as if it were a generated payload.
    """
    response.raise_for_status()
    content_type = response.headers.get("Content-Type", "")
    if "text/html" in content_type.lower():
        raise RuntimeError(
            f"LLMShield returned an HTML page instead of a payload response "
            f"(endpoint likely offline/tunnel down). Content-Type={content_type!r}, "
            f"body[:200]={response.text[:200]!r}"
        )

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

def llmshield_generate_payloads(waf_name: str, attack_type: str, techniques: str = None, probe_history: list[dict]|None = None, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase1", seed: int|None = None) -> str|None:
    data = {
        "waf_name": waf_name,
        "attack_type": attack_type,
        "technique": techniques,
        "max_new_tokens": max_new_tokens,
        "temperature": temperature,
        "adapter_name": adapter_name,
        "probe_history": probe_history,
        "seed": seed,
    }
    url = LLMSHIELD_ENDPOINT + "?action=" + "generate_payload"
    while True:
        try:
            response = requests.post(url, json=data, timeout=120)
            _validate_llmshield_response(response)
            return response.text
        except Exception as e:
            print(f"[Ext-LLMShield] {str(e)}. Retrying in 5s...")
            time.sleep(5)
            continue


def llmshield_generate_payloads_batch(items: list[dict]) -> list[str]:
    """Generate multiple payloads in a single request so the GPU processes them
    as one batch instead of one sequential forward pass per payload.

    Each item in `items` is a dict with the same keys as llmshield_generate_payloads
    (waf_name, attack_type, technique/probe_history, adapter_name, seed, ...).
    """
    data = {"items": items}
    url = LLMSHIELD_ENDPOINT + "?action=" + "generate_payload_batch"
    while True:
        try:
            response = requests.post(url, json=data, timeout=600)
            _validate_llmshield_response(response)
            return json.loads(response.text)
        except Exception as e:
            print(f"[Ext-LLMShield] {str(e)}. Retrying in 5s...")
            time.sleep(5)
            continue


def rag_retrieve(
    attack_type: str,
    waf_name: str,
    bypassed_payloads: list|None = None,
    initial_k: int = 10,
    final_k: int = 4,
    filter_rules_only: bool = True,
) -> dict:
    bypassed_payloads = bypassed_payloads or []
    resolved_attack_type = attack_type.strip()
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
        result = response.json()
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
