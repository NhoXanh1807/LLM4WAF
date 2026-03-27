
from dataclasses import dataclass
from sqlglot import Expression, parse_one, TokenError
import requests

PAYLOAD_PLACEHOLDER = "###payload###"

SQL_INJECTTION_CONTEXTS = {
    "STRING": [
        f"SELECT * FROM users WHERE username = '{PAYLOAD_PLACEHOLDER}'",
        f"SELECT * FROM users WHERE email = '{PAYLOAD_PLACEHOLDER}' AND active = 1",
    ],
    "NUMERIC": [
        f"SELECT * FROM users WHERE id = {PAYLOAD_PLACEHOLDER}",
        f"SELECT * FROM orders WHERE amount > {PAYLOAD_PLACEHOLDER} AND active = 1",
        f"SELECT * FROM users LIMIT {PAYLOAD_PLACEHOLDER}",
        f"SELECT * FROM products LIMIT 10 OFFSET {PAYLOAD_PLACEHOLDER}",
        f"SELECT * FROM orders LIMIT {PAYLOAD_PLACEHOLDER} OFFSET 0",
    ],
    "IDENTIFIER": [
        f"SELECT * FROM users ORDER BY {PAYLOAD_PLACEHOLDER}",
        f"SELECT * FROM users ORDER BY {PAYLOAD_PLACEHOLDER} DESC",
        f"SELECT * FROM {PAYLOAD_PLACEHOLDER} WHERE active = 1",
        f"SELECT * FROM users WHERE {PAYLOAD_PLACEHOLDER} IS NOT NULL",
    ],
    "COLUMN_LIST": [
        f"SELECT {PAYLOAD_PLACEHOLDER} FROM users",
    ],
    "ASC_DESC": [
        f"SELECT * FROM users ORDER BY id {PAYLOAD_PLACEHOLDER}",
    ],
}

@dataclass
class EvaluateSQLResult:
    payload: str
    safe_queries: list[str] = None
    harm_queries: list[str] = None
    error_queries: list[str] = None
@dataclass
class EvaluateXSSResult:
    payload: str
    is_safe: bool = None
    harms: None

def try_parse(sql):
    try:
        return parse_one(sql)
    except Exception as e:
        return None

def compare_trees(tree1, tree2):
    tree1_nodes = []
    tree2_nodes = []
    for node in tree1.walk():
        tree1_nodes.append(node)
    for node in tree2.walk():
        tree2_nodes.append(node)
    if len(tree1_nodes) != len(tree2_nodes):
        return False
    for node1, node2 in zip(tree1_nodes, tree2_nodes):
        if type(node1) != type(node2):
            return False
    return True

def evaluate_sql_payload(payload) -> EvaluateSQLResult:
    result = EvaluateSQLResult(payload, safe_queries=[], harm_queries=[], error_queries=[])
    for context in SQL_INJECTTION_CONTEXTS:
        for template in SQL_INJECTTION_CONTEXTS[context]:
            test_sql = template.replace(PAYLOAD_PLACEHOLDER, payload)
            safe_sql = template.replace(PAYLOAD_PLACEHOLDER, "1")
            test_tree = try_parse(test_sql)
            safe_tree = try_parse(safe_sql)
            # Payload phá vỡ cú pháp SQL
            if test_tree is None:
                result.error_queries.append(test_sql)
            else:
                # AST mới KHÁC cấu trúc với AST an toàn
                if not compare_trees(test_tree, safe_tree):
                    result.harm_queries.append(test_sql)
                # AST mới cùng cấu trúc với AST an toàn
                else:
                    result.safe_queries.append(test_sql)
    return result

def evaluate_xss_payload(payload) -> EvaluateXSSResult:
    try:
        res = requests.post("http://api.akng.io.vn:89/validate_payload", data=payload)
        return EvaluateXSSResult(
            payload=payload,
            is_safe=res.json()["data"]["is_safe"],
            harms=res.json()["data"]["harms"],
        )
    except Exception as e:
        return None