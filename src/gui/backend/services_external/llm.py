"""
OpenAI API client service for LLM interactions
"""

import requests
from dataclasses import asdict
from classes import PayloadResult
try:
    from ..config.settings import OPENAI_API_KEY, OPENAI_MODEL
except ImportError:
    from config.settings import OPENAI_API_KEY, OPENAI_MODEL

LLMSHIELD_ENDPOINT = "https://overrigged-savingly-nelle.ngrok-free.dev"

def chatgpt_completion(messages=[], model=None, response_format=None):
    if model is None:
        model = OPENAI_MODEL

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}",
    }
    body = {
        "model": model,
        "messages": messages,
        "response_format": response_format
    }
    response = requests.post(url, headers=headers, json=body)
    return response.json()


def llmshield_build_prompt(waf_name: str, attack_type: str, technique: str, probe_history: list[PayloadResult]|None = None) -> str|None:
    data = {
        "waf_name": waf_name,
        "attack_type": attack_type,
        "technique": technique,
        "probe_history": [asdict(p) for p in probe_history] if probe_history is not None else None
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
