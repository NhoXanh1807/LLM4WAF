
from sqlglot import Expression, parse_one, TokenError

def sql_template_1(injection_payload):
    return f"SELECT id, name FROM users WHERE age > '{injection_payload}'"

good_sql = sql_template_1("30")
sql_1 = sql_template_1("31")
sql_2 = sql_template_1("30' OR '1'='1--")

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

print(compare_trees(parse_one(good_sql), parse_one(sql_1)))  # Expected: True
print(compare_trees(parse_one(good_sql), parse_one(sql_2)))  # Expected: False