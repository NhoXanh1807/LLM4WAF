
from dataclasses import dataclass
from sqlglot import Expression, parse_one, TokenError
import requests

PAYLOAD_PLACEHOLDER = "###payload###"

# f"SELECT * FROM users WHERE username = 'akng'"

# Danh sách template SQL injection dạng string với PAYLOAD_PLACEHOLDER
SQL_INJECTION_TEMPLATES_STRINGS = [
    # ===== BASIC =====
    f"SELECT * FROM users WHERE username = '{PAYLOAD_PLACEHOLDER}'",
    f"SELECT * FROM users WHERE age = '{PAYLOAD_PLACEHOLDER}'",
    f"SELECT id, name FROM users WHERE age > '{PAYLOAD_PLACEHOLDER}'",
    f"SELECT * FROM users WHERE name LIKE '%{PAYLOAD_PLACEHOLDER}%'",

    # ===== AUTH =====
    f"SELECT * FROM users WHERE username = 'admin' AND password = '{PAYLOAD_PLACEHOLDER}'",
    f"SELECT * FROM users WHERE username = '{PAYLOAD_PLACEHOLDER}' AND password = '123456'",

    # ===== SEARCH =====
    f"SELECT * FROM products WHERE name LIKE '%{PAYLOAD_PLACEHOLDER}%' OR description LIKE '%{PAYLOAD_PLACEHOLDER}%'",
    f"SELECT * FROM orders WHERE status = 'active' AND ({PAYLOAD_PLACEHOLDER})",

    # ===== LOGIC =====
    f"SELECT * FROM users WHERE id = '{PAYLOAD_PLACEHOLDER}'",
    f"SELECT * FROM users WHERE id IN ('{PAYLOAD_PLACEHOLDER}')",

    # ===== ORDER / LIMIT =====
    f"SELECT * FROM users ORDER BY {PAYLOAD_PLACEHOLDER}",
    f"SELECT * FROM users ORDER BY created_at {PAYLOAD_PLACEHOLDER}",
    f"SELECT * FROM users LIMIT '{PAYLOAD_PLACEHOLDER}'",
    f"SELECT * FROM users LIMIT 10 OFFSET '{PAYLOAD_PLACEHOLDER}'",

    # ===== QUERY EXTENSION =====
    f"SELECT id, name FROM users WHERE id = '{PAYLOAD_PLACEHOLDER}'",
    f"SELECT * FROM users WHERE id = (SELECT {PAYLOAD_PLACEHOLDER})",
    f"SELECT * FROM users WHERE EXISTS (SELECT {PAYLOAD_PLACEHOLDER})",
    f"SELECT CASE WHEN ('{PAYLOAD_PLACEHOLDER}') THEN 1 ELSE 0 END",

    # ===== WRITE =====
    f"INSERT INTO users(name) VALUES ('{PAYLOAD_PLACEHOLDER}')",
    f"UPDATE users SET name = '{PAYLOAD_PLACEHOLDER}' WHERE id = 1",
    f"DELETE FROM users WHERE name = '{PAYLOAD_PLACEHOLDER}'",

    # ===== ADVANCED =====
    f"SELECT * FROM users WHERE LENGTH('{PAYLOAD_PLACEHOLDER}') > 3",
    f"SELECT * FROM users u JOIN orders o ON u.id = '{PAYLOAD_PLACEHOLDER}'",
    f"SELECT age, COUNT(*) FROM users GROUP BY {PAYLOAD_PLACEHOLDER}",
    f"SELECT age, COUNT(*) FROM users GROUP BY age HAVING COUNT(*) > '{PAYLOAD_PLACEHOLDER}'",
    f"SELECT * FROM users WHERE JSON_EXTRACT(data, '$.role') = '{PAYLOAD_PLACEHOLDER}'",
    f"EXEC('{PAYLOAD_PLACEHOLDER}')",
    f"SELECT {PAYLOAD_PLACEHOLDER} FROM users",
]

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
    for template in SQL_INJECTION_TEMPLATES_STRINGS:
        test_sql = template.replace(PAYLOAD_PLACEHOLDER, payload)
        safe_sql = template.replace(PAYLOAD_PLACEHOLDER, "1")
        test_tree = try_parse(test_sql)
        safe_tree = try_parse(safe_sql)
        # Payload làm sai cú pháp SQL
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