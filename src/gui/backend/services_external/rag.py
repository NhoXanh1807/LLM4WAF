import requests
LLMSHIELD_ENDPOINT = "https://overrigged-savingly-nelle.ngrok-free.dev"


def rag_retrieve(
    attack_type: str, 
    waf_name: str, 
    bypassed_payloads: list = [], 
    initial_k: int = 10, 
    final_k:int = 5,
    filter_rules_only: bool = True
) -> dict|None:
    try:
        data = {
            "attack_type": attack_type,
            "waf_name": waf_name,
            "bypassed_payloads": bypassed_payloads,
            "initial_k": initial_k,
            "final_k": final_k,
            "filter_rules_only": filter_rules_only
        }
        url = LLMSHIELD_ENDPOINT + "?action=" + "rag_retrieve"
        response = requests.post(url, json=data)
        """
        {
            "rag_enabled": self.enable_rag,
            "num_queries": 0,
            "num_docs_all": 0,
            "num_docs_filtered": 0,
            "sources": [],
        }
        """
        return response.json()
    except Exception as e:
        print(f"Error in rag_retrieve: {str(e)}")
        return None