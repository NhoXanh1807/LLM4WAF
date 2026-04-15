
import urllib
import requests
import unicodedata
import html
import re
from sqlglot import parse_one
from dataclasses import dataclass

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
    harms: dict|None = None
    
HOMOGLYPH_MAP = {
    'а': 'a', 'ɑ': 'a', 'α': 'a', 'ａ': 'a',#
    'Ь': 'b', 'ƅ': 'b', 'ｂ': 'b',#
    'с': 'c', 'ϲ': 'c', 'ｃ': 'c', #
    'ԁ': 'd', 'ɗ': 'd', 'ｄ': 'd', #
    'е': 'e', '℮': 'e', 'ｅ': 'e', #
    'ƒ': 'f', 'ｆ': 'f', #
    'ɡ': 'g', 'ｇ': 'g', #
    'һ': 'h', 'ｈ': 'h', #
    'і': 'i', 'ɩ': 'i', 'ｉ': 'i', #
    'ј': 'j', 'ｊ': 'j', #
    'κ': 'k', 'ｋ': 'k', #
    'ⅼ': 'l', 'ӏ': 'l', 'ｌ': 'l', #
    'ｍ': 'm', 'ṃ': 'm', #
    'ո': 'n', 'ｎ': 'n', #
    'о': 'o', 'ο': 'o', 'օ': 'o', 'ｏ': 'o', '0': 'o', #
    'р': 'p', 'ρ': 'p', 'ｐ': 'p', #
    'զ': 'q', 'ｑ': 'q', #
    'г': 'r', 'ｒ': 'r', #
    'ѕ': 's', 'ｓ': 's', #
    'τ': 't', 'ｔ': 't', #
    'υ': 'u', 'ս': 'u', 'ｕ': 'u', #
    'ν': 'v', 'ⅴ': 'v', 'ｖ': 'v', #
    'ѡ': 'w', 'ｗ': 'w', #
    'х': 'x', 'χ': 'x', 'ｘ': 'x', #
    'у': 'y', 'γ': 'y', 'ｙ': 'y', #
    'ᴢ': 'z', 'ｚ': 'z', #
    'Α': 'A', 'А': 'A', 'Ａ': 'A', #
    'Β': 'B', 'В': 'B', 'Ｂ': 'B', #
    'С': 'C', 'Ϲ': 'C', 'Ｃ': 'C', #
    'Ꭰ': 'D', 'Ｄ': 'D', #
    'Ε': 'E', 'Е': 'E', 'Ｅ': 'E', #
    'Ϝ': 'F', 'Ｆ': 'F', #
    'Ｇ': 'G', #
    'Η': 'H', 'Н': 'H', 'Ｈ': 'H', #
    'Ι': 'I', 'І': 'I', 'Ｉ': 'I', #
    'Ј': 'J', 'Ｊ': 'J', #
    'Κ': 'K', 'К': 'K', 'Ｋ': 'K', #
    'Ꮮ': 'L', 'Ｌ': 'L', #
    'Μ': 'M', 'М': 'M', 'Ｍ': 'M', #
    'Ν': 'N', 'Ｎ': 'N', #
    'Ο': 'O', 'О': 'O', 'Օ': 'O', 'Ｏ': 'O', '0': 'O',#
    'Ρ': 'P', 'Р': 'P', 'Ｐ': 'P',#
    'Ｑ': 'Q',#
    'Ꮢ': 'R', 'Ｒ': 'R',#
    'Ѕ': 'S', 'Ｓ': 'S',#
    'Τ': 'T', 'Т': 'T', 'Ｔ': 'T',#
    'Ս': 'U', 'Ｕ': 'U',#
    'Ⅴ': 'V', 'Ｖ': 'V',#
    'Ｗ': 'W',#
    'Χ': 'X', 'Х': 'X', 'Ｘ': 'X',#
    'Υ': 'Y', 'Ү': 'Y', 'Ｙ': 'Y',#
    'Ζ': 'Z', 'Ｚ': 'Z',#
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',#
    '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',#
    '⁰': '0', '¹': '1', '²': '2', '³': '3',#
}
def _normalize_homoglyphs(s: str) -> str:
    if s is None:
        return None
    return ''.join(HOMOGLYPH_MAP.get(c, c) for c in s)

DECODERS = {
    "URL": lambda payload: urllib.parse.unquote(payload),
    "HTML": lambda payload: html.unescape(payload),
    "UNICODE": lambda payload: None if payload is None else unicodedata.normalize("NFKC", payload),
    "HOMOGLYPH": lambda payload: _normalize_homoglyphs(payload),
    "CUSTOM": lambda payload: payload
        .replace("%2O", "%20")
        .replace("%O9", "%09")
        .replace("%OA", "%0A")
        .replace("%6O", "%60")
        .replace("\\uOO", "\\u00")
        .replace("\\OO", "\\00"),
    "CUSTOM2": lambda payload: re.sub(r'(\d)OO', r'\g<1>00',
        re.sub(r'(\d\d)O', r'\g<1>0', 
            re.sub(r'(\d)O(\d)', r'\g<1>0\g<2>', payload)
        )
    )
}

def _fully_decode_payload(payload):
    flag = True
    decode_stack = []
    while flag:
        new_p_0 = payload
        for decoder in DECODERS:
            old_p_0 = new_p_0
            new_p_1 = DECODERS[decoder](old_p_0)
            if new_p_1 != old_p_0:
                decode_stack.append((decoder, old_p_0, new_p_1))
                new_p_0 = new_p_1
        if new_p_0 == payload:
            flag = False
        else:
            payload = new_p_0
    return payload, decode_stack



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
        payload, decode_stack = _fully_decode_payload(payload)
    result = EvaluateSQLResult(payload, safe_queries=[], harm_queries=[], error_queries=[])
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

def evaluate_xss_payload(payload, auto_decode=True) -> EvaluateXSSResult:
    if auto_decode:
        payload, decode_stack = _fully_decode_payload(payload)
    try:
        res = requests.post("http://api.akng.io.vn:89/validate_payload", data=payload)
        return EvaluateXSSResult(
            payload=payload,
            is_safe=res.json()["data"]["is_safe"],
            harms=res.json()["data"]["harms"],
        )
    except Exception as e:
        return None