"""
LLM API client service for OpenAI and Claude (Anthropic) interactions
"""

import json
import requests
from dataclasses import asdict
from classes import PayloadResult
try:
    from ..config.settings import OPENAI_API_KEY, OPENAI_MODEL, CLAUDE_API_KEY, CLAUDE_MODEL
except ImportError:
    from config.settings import OPENAI_API_KEY, OPENAI_MODEL, CLAUDE_API_KEY, CLAUDE_MODEL

def claude_completion(messages=[], model=None, response_format=None):
    """
    Call Claude (Anthropic) API with the same interface as chatgpt_completion.
    Converts OpenAI-style messages to Anthropic format and returns OpenAI-compatible response.
    """
    if model is None:
        model = CLAUDE_MODEL

    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "Content-Type": "application/json",
        "x-api-key": CLAUDE_API_KEY,
        "anthropic-version": "2023-06-01",
    }

    # Separate system message from user/assistant messages
    system_content = None
    anthropic_messages = []
    for msg in messages:
        if msg["role"] == "system":
            system_content = msg["content"]
        else:
            anthropic_messages.append({"role": msg["role"], "content": msg["content"]})

    body = {
        "model": model,
        "max_tokens": 8192,
        "messages": anthropic_messages,
    }
    if system_content:
        body["system"] = system_content

    # If response_format with json_schema is requested, instruct Claude via system prompt
    if response_format and response_format.get("type") == "json_schema":
        schema = response_format["json_schema"]["schema"]
        json_instruction = (
            "\n\nIMPORTANT: You MUST respond with valid JSON only, no markdown, no code fences. "
            f"The JSON must conform to this schema: {json.dumps(schema)}"
        )
        if system_content:
            body["system"] = system_content + json_instruction
        else:
            body["system"] = json_instruction

    response = requests.post(url, headers=headers, json=body)
    result = response.json()

    # Convert Anthropic response to OpenAI-compatible format
    content_text = ""
    if "content" in result and len(result["content"]) > 0:
        content_text = result["content"][0].get("text", "")
        # Strip markdown code fences if present
        if content_text.strip().startswith("```"):
            lines = content_text.strip().split("\n")
            # Remove first line (```json or ```) and last line (```)
            if lines[-1].strip() == "```":
                lines = lines[1:-1]
            content_text = "\n".join(lines)

    return {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": content_text,
            }
        }],
        "model": result.get("model", model),
        "usage": result.get("usage", {}),
    }


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
