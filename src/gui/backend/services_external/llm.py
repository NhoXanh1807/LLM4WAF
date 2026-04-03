"""
OpenAI API client service for LLM interactions
"""

import json

import requests
try:
    from ..config.settings import OPENAI_API_KEY, OPENAI_MODEL
except ImportError:
    from config.settings import OPENAI_API_KEY, OPENAI_MODEL


def chatgpt_completion(messages=[], model=None, response_format=None):
    """
    Send a chat completion request to OpenAI API

    Args:
        messages (list): List of message dicts with 'role' and 'content'
        model (str): OpenAI model name (default: from settings)
        response_format (dict): Response format specification (e.g., JSON schema)

    Returns:
        dict: OpenAI API response
    """
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

def llmshield_build_prompt(waf_name: str, attack_type: str, technique: str, probe_history: list|None = None) -> str:
    data = {
        "waf_name": waf_name,
        "attack_type": attack_type,
        "technique": technique,
        "probe_history": probe_history
    }
    url = "http://api.akng.io.vn:89/llm?action=build_prompt"
    response = requests.post(url, params=json.dumps(data))
    return response.text

def llmshield_generate_response(prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase1") -> dict:
    data = {
        "max_new_tokens": max_new_tokens,
        "temperature": temperature,
        "adapter_name": adapter_name
    }
    url = "http://api.akng.io.vn:89/llm?action=generate"
    response = requests.post(url, params=data, data=prompt)
    return response.text

def llmshield_generate_payloads(waf_name: str, attack_type: str, techniques: str, probe_history: list|None = None, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase1") -> dict:
    data = {
        "waf_name": waf_name,
        "attack_type": attack_type,
        "technique": techniques,
        "probe_history": probe_history,
        "max_new_tokens": max_new_tokens,
        "temperature": temperature,
        "adapter_name": adapter_name
    }
    url = "http://api.akng.io.vn:89/llm?action=generate_payload"
    response = requests.post(url, params=data)
    return response.text

