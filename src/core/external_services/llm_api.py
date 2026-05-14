"""
LLM API client service for OpenAI and Claude (Anthropic) interactions
"""

import json
import requests
from config.settings import OPENAI_API_KEY, OPENAI_MODEL, CLAUDE_API_KEY, CLAUDE_MODEL

def claude_completion(messages=[], model=None, response_format=None):
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
        "max_tokens": 16000,
        "messages": anthropic_messages,
    }
    if system_content:
        body["system"] = system_content

    # If response_format with json_schema is requested, instruct Claude via system prompt
    if response_format and response_format.get("type") == "json_schema":
        schema = response_format["json_schema"]["schema"]
        json_instruction = (
            "\n\nIMPORTANT: You MUST respond with valid JSON only, no markdown, no code fences, ensure valid escape like \\s \\( not \s \(:"
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

