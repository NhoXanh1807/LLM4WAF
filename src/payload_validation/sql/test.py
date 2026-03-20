
from sqlglot import Expression, parse_one, TokenError
# =========================
# 🔴 SQL TEMPLATES
# =========================

# 1. WHERE string
def tpl_where_string(payload):
    return f"SELECT * FROM users WHERE username = '{payload}'"

# 2. WHERE number
def tpl_where_number(payload):
    return f"SELECT * FROM users WHERE age = {payload}"

# 3. WHERE comparison (original)
def tpl_where_compare(payload):
    return f"SELECT id, name FROM users WHERE age > '{payload}'"

# 4. LIKE
def tpl_like(payload):
    return f"SELECT * FROM users WHERE name LIKE '%{payload}%'"

# 5. ORDER BY
def tpl_order_by(payload):
    return f"SELECT * FROM users ORDER BY {payload}"

# 6. UNION context
def tpl_union(payload):
    return f"SELECT id, name FROM users WHERE id = {payload}"

# 7. Boolean-based
def tpl_boolean(payload):
    return f"SELECT * FROM users WHERE id = {payload}"

# 8. Time-based
def tpl_time(payload):
    return f"SELECT * FROM users WHERE id = {payload}"

# 9. INSERT
def tpl_insert(payload):
    return f"INSERT INTO users(name) VALUES ('{payload}')"

# 10. UPDATE
def tpl_update(payload):
    return f"UPDATE users SET name = '{payload}' WHERE id = 1"

# 11. DELETE
def tpl_delete(payload):
    return f"DELETE FROM users WHERE name = '{payload}'"

# 12. Subquery
def tpl_subquery(payload):
    return f"SELECT * FROM users WHERE id = (SELECT {payload})"

# 13. Function context
def tpl_function(payload):
    return f"SELECT * FROM users WHERE LENGTH('{payload}') > 3"

# 14. GROUP BY
def tpl_group_by(payload):
    return f"SELECT age, COUNT(*) FROM users GROUP BY {payload}"

# 15. HAVING
def tpl_having(payload):
    return f"SELECT age, COUNT(*) FROM users GROUP BY age HAVING COUNT(*) > {payload}"

# 16. LIMIT / OFFSET
def tpl_limit(payload):
    return f"SELECT * FROM users LIMIT {payload}"

# 17. JOIN condition
def tpl_join(payload):
    return f"SELECT * FROM users u JOIN orders o ON u.id = {payload}"

# =========================
# 📋 TEMPLATE LIST
# =========================

SQL_INJECTION_TEMPLATES = [
    tpl_where_string,
    tpl_where_number,
    tpl_where_compare,
    tpl_like,
    tpl_order_by,
    tpl_union,
    tpl_boolean,
    tpl_time,
    tpl_insert,
    tpl_update,
    tpl_delete,
    tpl_subquery,
    tpl_function,
    tpl_group_by,
    tpl_having,
    tpl_limit,
    tpl_join,
]

def try_parse(sql):
    try:
        return parse_one(sql)
    except TokenError as e:
        print(f"TokenError: {e}")
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

def validate_sql_payload(payload):
    harm_counter = 0
    for template in SQL_INJECTION_TEMPLATES:
        test_tree = try_parse(template(payload))
        safe_tree = try_parse(template("1"))
        if test_tree is None or safe_tree is None:
            return False
        
        if not compare_trees(test_tree, safe_tree):
            harm_counter += 1
    return harm_counter