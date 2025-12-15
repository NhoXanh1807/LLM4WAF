"""
Payload generation service using LLM
"""

import json
from .llm_service import chatgpt_completion
from ..config.settings import OPENAI_MODEL, DEFAULT_NUM_PAYLOADS
from ..config.prompts import RED_TEAM_SYSTEM_PROMPT, get_red_team_user_prompt


def generate_payloads_from_domain_waf_info(waf_info, attack_type, num_of_payloads=None):
    """
    Generate attack payloads using GPT-4 based on WAF fingerprint

    Args:
        waf_info (dict): WAF detection information
        attack_type (str): Type of attack (xss_dom, sql_injection, etc.)
        num_of_payloads (int): Number of payloads to generate

    Returns:
        dict: OpenAI response with generated payloads
    """
    if num_of_payloads is None:
        num_of_payloads = DEFAULT_NUM_PAYLOADS

    # Build messages for LLM
    messages = [
        {
            "role": "system",
            "content": RED_TEAM_SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": get_red_team_user_prompt(
                json.dumps(waf_info),
                attack_type,
                num_of_payloads
            )
        }
    ]

    # Define JSON schema for structured output
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "PayloadList",
            "schema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "payload": {
                                    "type": "string",
                                    "description": "The attack payload",
                                },
                                "instruction": {
                                    "type": "string",
                                    "description": "Short instruction in between 3 to 5 sentences to use the payload",
                                },
                            },
                            "required": ["payload", "instruction"],
                        }
                    }
                },
                "required": ["items"]
            }
        },
    }

    # Call LLM
    chat_result = chatgpt_completion(
        messages=messages,
        model=OPENAI_MODEL,
        response_format=response_format
    )

    # Include messages in response for debugging
    chat_result["messages"] = messages
    return chat_result
