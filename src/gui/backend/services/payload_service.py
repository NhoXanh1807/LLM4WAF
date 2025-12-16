"""
Payload generation service using LLM
"""

import json
import random
try:
    from .llm_service import chatgpt_completion
    from ..config.settings import OPENAI_MODEL, DEFAULT_NUM_PAYLOADS
    from ..config.prompts import RED_TEAM_SYSTEM_PROMPT, get_red_team_user_prompt
    from ..llm_helper.llm import gemma_2b_model
except ImportError:
    from services.llm_service import chatgpt_completion
    from config.settings import OPENAI_MODEL, DEFAULT_NUM_PAYLOADS
    from config.prompts import RED_TEAM_SYSTEM_PROMPT, get_red_team_user_prompt
    from llm_helper.llm import gemma_2b_model

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

def generate_payloads_by_local_llm(waf_info, attack_type, num_of_payloads=None):
    techniques = {
        "xss":[
            "SVG Event Handler", "Unicode Normalization", "IMG Tag with OnError",
            "Body Tag with OnLoad", "Javascript Pseudo-protocol in A Tag",
            "Case Manipulation (<ScRiPt>)", "Attribute Injection (breaking out of quotes)"
        ],
        "sqli": [
            "SVG Event Handler", "Unicode Normalization", "IMG Tag with OnError",
            "Body Tag with OnLoad", "Javascript Pseudo-protocol in A Tag",
            "Case Manipulation (<ScRiPt>)", "Attribute Injection (breaking out of quotes)"
        ]
    }
    results = []
    for i in range(num_of_payloads):
        if attack_type.contains("xss"):
            selected_techniques = random.sample(techniques["xss"], random.randint(1, len(techniques["xss"])))
        elif attack_type.contains("sql"):
            selected_techniques = random.sample(techniques["sqli"], random.randint(1, len(techniques["sqli"])))
        technique = "+".join(selected_techniques)
        
        genCfg = GenerationConfig(max_new_tokens=64, do_sample=True, temperature=0.9)
        prompt = (
            f"Generate a {attack_type} payload using techniques {technique} to bypass WAF {waf_info}. "
            "Output ONLY the payload string. Do NOT add explanations or comments. "
            "Do NOT wrap it in code fences."
        )
        generated = gemma_2b_model.generate_once(prompt, genCfg)
        generated = generated.replace("model\n", "").strip()
        results.append(generated)
    return results
