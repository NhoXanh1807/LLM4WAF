
from sqlglot import parse_one
from helpers import fully_decode_payload
from dtos import EvaluateSQLResult

PAYLOAD_PLACEHOLDER = "###payload###"
SQL_INJECTTION_CONTEXTS = {
    "STRING": [
        (f"SELECT * FROM users WHERE username = '{PAYLOAD_PLACEHOLDER}'", "1"),
        (f"SELECT * FROM users WHERE email = '{PAYLOAD_PLACEHOLDER}' AND active = 1", "1"),
    ],
    "NUMERIC": [
        (f"SELECT * FROM users WHERE id = {PAYLOAD_PLACEHOLDER}", "1"),
        (f"SELECT * FROM orders WHERE amount > {PAYLOAD_PLACEHOLDER} AND active = 1", "1"),
        (f"SELECT * FROM users LIMIT {PAYLOAD_PLACEHOLDER}", "10"),
        (f"SELECT * FROM products LIMIT 10 OFFSET {PAYLOAD_PLACEHOLDER}", "10"),
        (f"SELECT * FROM orders LIMIT {PAYLOAD_PLACEHOLDER} OFFSET 0", "10"),
    ],
    "IDENTIFIER": [
        (f"SELECT * FROM users ORDER BY {PAYLOAD_PLACEHOLDER}", "name"),
        (f"SELECT * FROM users ORDER BY {PAYLOAD_PLACEHOLDER} DESC", "name"),
        (f"SELECT * FROM {PAYLOAD_PLACEHOLDER} WHERE active = 1", "users"),
        (f"SELECT * FROM users WHERE {PAYLOAD_PLACEHOLDER} IS NOT NULL", "name"),
    ],
    "COLUMN_LIST": [
        (f"SELECT {PAYLOAD_PLACEHOLDER} FROM users", "name"),
    ],
    "ASC_DESC": [
        (f"SELECT * FROM users ORDER BY id {PAYLOAD_PLACEHOLDER}", "DESC"),
    ],
}



def _try_parse_sql_ast(sql):
    try:
        return parse_one(sql)
    except Exception as e:
        return None


def _compare_trees(tree1, tree2):
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


def evaluate_sql_payload(payload, auto_decode=True) -> EvaluateSQLResult:
    if auto_decode:
        payload, decode_stack = fully_decode_payload(payload)
    else:
        decode_stack = []
    result = EvaluateSQLResult(payload, safe_queries=[], harm_queries=[], error_queries=[], decode_stack=decode_stack)
    for context in SQL_INJECTTION_CONTEXTS:
        for template, safe_payload in SQL_INJECTTION_CONTEXTS[context]:
            test_sql = template.replace(PAYLOAD_PLACEHOLDER, payload)
            safe_sql = template.replace(PAYLOAD_PLACEHOLDER, safe_payload)
            test_tree = _try_parse_sql_ast(test_sql)
            safe_tree = _try_parse_sql_ast(safe_sql)
            # Payload phá vỡ cú pháp SQL
            if test_tree is None:
                result.error_queries.append(test_sql)
            else:
                # AST mới KHÁC cấu trúc với AST an toàn
                if not _compare_trees(test_tree, safe_tree):
                    result.harm_queries.append(test_sql)
                # AST mới cùng cấu trúc với AST an toàn
                else:
                    result.safe_queries.append(test_sql)
    return result
