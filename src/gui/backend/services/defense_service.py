# """
# Defense rule generation service using LLM
# """

# import json
# try:
#     from .llm_service import chatgpt_completion
#     from ..config.settings import OPENAI_MODEL, DEFAULT_NUM_DEFENSE_RULES
#     from ..config.prompts import BLUE_TEAM_SYSTEM_PROMPT, get_blue_team_user_prompt
# except ImportError:
#     from services.llm_service import chatgpt_completion
#     from config.settings import OPENAI_MODEL, DEFAULT_NUM_DEFENSE_RULES
#     from config.prompts import BLUE_TEAM_SYSTEM_PROMPT, get_blue_team_user_prompt


# def generate_defend_rules_and_instructions(waf_info, bypassed_payloads, bypassed_instructions):
#     """
#     Generate ModSecurity defense rules using GPT-4

#     Args:
#         waf_info (dict): WAF detection information
#         bypassed_payloads (list): List of payloads that bypassed the WAF
#         bypassed_instructions (list): Instructions for each bypassed payload

#     Returns:
#         dict: OpenAI response with generated defense rules
#     """
#     num_of_rules = DEFAULT_NUM_DEFENSE_RULES

#     # Build messages for LLM
#     messages = [
#         {
#             "role": "system",
#             "content": BLUE_TEAM_SYSTEM_PROMPT
#         },
#         {
#             "role": "user",
#             "content": get_blue_team_user_prompt(
#                 json.dumps(waf_info),
#                 json.dumps(bypassed_payloads),
#                 json.dumps(bypassed_instructions),
#                 num_of_rules
#             )
#         }
#     ]

#     # Define JSON schema for structured output
#     response_format = {
#         "type": "json_schema",
#         "json_schema": {
#             "name": "DefenseRuleList",
#             "schema": {
#                 "type": "object",
#                 "properties": {
#                     "items": {
#                         "type": "array",
#                         "items": {
#                             "type": "object",
#                             "properties": {
#                                 "rule": {
#                                     "type": "string",
#                                     "description": "The WAF rule or configuration to implement",
#                                 },
#                                 "instructions": {
#                                     "type": "string",
#                                     "description": "Short instructions on how to implement the rule",
#                                 },
#                             },
#                             "required": ["rule", "instructions"],
#                         }
#                     }
#                 },
#                 "required": ["items"]
#             }
#         },
#     }

#     # Call LLM
#     chat_result = chatgpt_completion(
#         messages=messages,
#         model=OPENAI_MODEL,
#         response_format=response_format
#     )

#     # Include messages in response for debugging
#     chat_result["messages"] = messages
#     return chat_result

"""
Defense rule generation service using LLM
ENHANCED WITH RAG SUPPORT
"""

import json
try:
    from .llm_service import chatgpt_completion
    from ..config.settings import OPENAI_MODEL, DEFAULT_NUM_DEFENSE_RULES
    from ..config.prompts import BLUE_TEAM_SYSTEM_PROMPT, get_blue_team_user_prompt
    # Import RAG service
    from ....RAG.rag_service import enhance_defense_generation
except ImportError:
    from services.llm_service import chatgpt_completion
    from config.settings import OPENAI_MODEL, DEFAULT_NUM_DEFENSE_RULES
    from config.prompts import BLUE_TEAM_SYSTEM_PROMPT, get_blue_team_user_prompt
    # Import RAG service
    from ....RAG.rag_service import enhance_defense_generation


def generate_defend_rules_and_instructions(waf_info, bypassed_payloads, bypassed_instructions, 
                                           enable_rag=True, docs_folder="./docs/" , filter_rules_only=True):
    """
    Generate ModSecurity defense rules using GPT-4
    ENHANCED: Now supports RAG-based context enrichment

    Args:
        waf_info (dict): WAF detection information
        bypassed_payloads (list): List of payloads that bypassed the WAF
        bypassed_instructions (list): Instructions for each bypassed payload
        enable_rag (bool): Whether to use RAG for context enhancement (default: True)
        docs_folder (str): Path to RAG documents folder (default: "./docs/")

    Returns:
        dict: OpenAI response with generated defense rules (includes RAG metadata if used)
    """
    num_of_rules = DEFAULT_NUM_DEFENSE_RULES

    # Generate base user prompt using existing function
    base_user_prompt = get_blue_team_user_prompt(
        json.dumps(waf_info),
        json.dumps(bypassed_payloads),
        json.dumps(bypassed_instructions),
        num_of_rules
    )
    
    # Enhance with RAG if enabled
    if enable_rag:
        rag_result = enhance_defense_generation(
            waf_info=waf_info,
            bypassed_payloads=bypassed_payloads,
            bypassed_instructions=bypassed_instructions,
            base_user_prompt=base_user_prompt,
            docs_folder=docs_folder,
            enable_rag=True,
            filter_rules_only=filter_rules_only
        )
        
        user_prompt = rag_result["enhanced_prompt"]
        rag_metadata = {
            "rag_used": rag_result["rag_used"],
            "sources": rag_result["sources"],
            "num_docs": rag_result.get("num_docs", 0),
            "num_queries": rag_result.get("num_queries", 0)
        }
    else:
        user_prompt = base_user_prompt
        rag_metadata = {
            "rag_used": False,
            "sources": [],
            "num_docs": 0,
            "num_queries": 0
        }

    # Build messages for LLM
    messages = [
        {
            "role": "system",
            "content": BLUE_TEAM_SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": user_prompt
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

    # Include messages and RAG metadata in response for debugging
    chat_result["messages"] = messages
    chat_result["rag_metadata"] = rag_metadata
    
    return chat_result