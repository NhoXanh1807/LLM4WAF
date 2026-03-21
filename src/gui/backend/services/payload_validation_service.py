
from dataclasses import dataclass
from sqlglot import Expression, parse_one, TokenError
import requests

# =========================
# 🔴 BASIC TEMPLATES
# =========================

def tpl_where_string(payload):
    return f"SELECT * FROM users WHERE username = '{payload}'"

def tpl_where_number(payload):
    return f"SELECT * FROM users WHERE age = '{payload}'"

def tpl_where_compare(payload):
    return f"SELECT id, name FROM users WHERE age > '{payload}'"

def tpl_like(payload):
    return f"SELECT * FROM users WHERE name LIKE '%{payload}%'"

# =========================
# 🔐 AUTH / LOGIN (IMPORTANT)
# =========================

def tpl_login(payload):
    return f"""
    SELECT * FROM users 
    WHERE username = 'admin' AND password = '{payload}'
    """

def tpl_login_user(payload):
    return f"""
    SELECT * FROM users 
    WHERE username = '{payload}' AND password = '123456'
    """

# =========================
# 🔍 SEARCH / FILTER
# =========================

def tpl_search(payload):
    return f"""
    SELECT * FROM products 
    WHERE name LIKE '%{payload}%' 
       OR description LIKE '%{payload}%'
    """

def tpl_filter(payload):
    return f"""
    SELECT * FROM orders 
    WHERE status = 'active' AND ({payload})
    """

# =========================
# 🔢 ORDER / LIMIT
# =========================

def tpl_order_by(payload):
    return f"SELECT * FROM users ORDER BY {payload}"

def tpl_order_direction(payload):
    return f"""
    SELECT * FROM users 
    ORDER BY created_at {payload}
    """

def tpl_limit(payload):
    return f"SELECT * FROM users LIMIT '{payload}'"

def tpl_limit_offset(payload):
    return f"""
    SELECT * FROM users LIMIT 10 OFFSET '{payload}'
    """

# =========================
# 🔗 LOGIC / BOOLEAN
# =========================

def tpl_boolean(payload):
    return f"SELECT * FROM users WHERE id = '{payload}'"

def tpl_in_clause(payload):
    return f"""
    SELECT * FROM users WHERE id IN ('{payload}')
    """

# =========================
# 🔄 QUERY EXTENSION
# =========================

def tpl_union(payload):
    return f"SELECT id, name FROM users WHERE id = '{payload}'"

def tpl_subquery(payload):
    return f"""
    SELECT * FROM users WHERE id = (SELECT {payload})
    """

def tpl_exists(payload):
    return f"""
    SELECT * FROM users WHERE EXISTS (SELECT {payload})
    """

def tpl_case_when(payload):
    return f"""
    SELECT CASE WHEN ('{payload}') THEN 1 ELSE 0 END
    """

# =========================
# ✏️ WRITE OPERATIONS
# =========================

def tpl_insert(payload):
    return f"INSERT INTO users(name) VALUES ('{payload}')"

def tpl_update(payload):
    return f"UPDATE users SET name = '{payload}' WHERE id = 1"

def tpl_delete(payload):
    return f"DELETE FROM users WHERE name = '{payload}'"

# =========================
# ⚙️ ADVANCED / SPECIAL
# =========================

def tpl_function(payload):
    return f"SELECT * FROM users WHERE LENGTH('{payload}') > 3"

def tpl_join(payload):
    return f"""
    SELECT * FROM users u 
    JOIN orders o ON u.id = '{payload}'
    """

def tpl_group_by(payload):
    return f"""
    SELECT age, COUNT(*) FROM users GROUP BY {payload}
    """

def tpl_having(payload):
    return f"""
    SELECT age, COUNT(*) FROM users 
    GROUP BY age 
    HAVING COUNT(*) > '{payload}'
    """

def tpl_json(payload):
    return f"""
    SELECT * FROM users 
    WHERE JSON_EXTRACT(data, '$.role') = '{payload}'
    """

def tpl_exec(payload):
    return f"EXEC('{payload}')"

def tpl_column(payload):
    return f"SELECT {payload} FROM users"


# =========================
# 📋 TEMPLATE LIST (FINAL)
# =========================

SQL_INJECTION_TEMPLATES = [
    # ===== BASIC =====
    tpl_where_string,
    tpl_where_number,
    tpl_where_compare,
    tpl_like,

    # ===== AUTH =====
    tpl_login,
    tpl_login_user,

    # ===== SEARCH =====
    tpl_search,
    tpl_filter,

    # ===== LOGIC =====
    tpl_boolean,
    tpl_in_clause,

    # ===== ORDER / LIMIT =====
    tpl_order_by,
    tpl_order_direction,
    tpl_limit,
    tpl_limit_offset,

    # ===== QUERY EXTENSION =====
    tpl_union,
    tpl_subquery,
    tpl_exists,
    tpl_case_when,

    # ===== WRITE =====
    tpl_insert,
    tpl_update,
    tpl_delete,

    # ===== ADVANCED =====
    tpl_function,
    tpl_join,
    tpl_group_by,
    tpl_having,
    tpl_json,
    tpl_exec,
    tpl_column,
]

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
    
def evaluate_sql_payload(payload) -> EvaluateSQLResult:
    result = EvaluateSQLResult(payload, safe_queries=[], harm_queries=[], error_queries=[])
    for template in SQL_INJECTION_TEMPLATES:
        test_sql = template(payload)
        test_tree = try_parse(test_sql)
        safe_tree = try_parse(template("1"))
        if test_tree is None:
            result.error_queries.append(test_sql)
        else:
            if not compare_trees(test_tree, safe_tree):
                result.harm_queries.append(test_sql)
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