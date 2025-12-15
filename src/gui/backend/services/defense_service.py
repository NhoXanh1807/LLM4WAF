"""
Defense rule generation service using LLM
"""

import json
from .llm_service import chatgpt_completion
from ..config.settings import OPENAI_MODEL, DEFAULT_NUM_DEFENSE_RULES
from ..config.prompts import BLUE_TEAM_SYSTEM_PROMPT, get_blue_team_user_prompt


def generate_defend_rules_and_instructions(waf_info, bypassed_payloads, bypassed_instructions):
    """
    Generate ModSecurity defense rules using GPT-4

    Args:
        waf_info (dict): WAF detection information
        bypassed_payloads (list): List of payloads that bypassed the WAF
        bypassed_instructions (list): Instructions for each bypassed payload

    Returns:
        dict: OpenAI response with generated defense rules
    """
    num_of_rules = DEFAULT_NUM_DEFENSE_RULES

    # Build messages for LLM
    messages = [
        {
            "role": "system",
            "content": BLUE_TEAM_SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": get_blue_team_user_prompt(
                json.dumps(waf_info),
                json.dumps(bypassed_payloads),
                json.dumps(bypassed_instructions),
                num_of_rules
            )
        }
    ]

    # Define JSON schema for structured output
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "DefenseRuleList",
            "schema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "rule": {
                                    "type": "string",
                                    "description": "The WAF rule or configuration to implement",
                                },
                                "instructions": {
                                    "type": "string",
                                    "description": "Short instructions on how to implement the rule",
                                },
                            },
                            "required": ["rule", "instructions"],
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
