"""
OpenAI API client service for LLM interactions
"""

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

def generate_response(prompt, model_name="GEMMA_2B", adapter_name="phase1", max_new_tokens=128, temperature=0.7):
    try:
        res = requests.post(f"http://api.akng.io.vn:89/generation?model_name={model_name}&adapter_name={adapter_name}&max_new_tokens={max_new_tokens}&temperature={temperature}", data=prompt)
        if (
            res.status_code == 200
            and "data" in res.json()
        ):
            return res.json()["data"]
        else:
            return None
    except Exception as e:
        print(f"Error calling generation API: {e}")
        return None