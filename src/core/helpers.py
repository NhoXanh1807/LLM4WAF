
import urllib
import unicodedata
import html
import re

_HOMOGLYPH_MAP = {
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
    return ''.join(_HOMOGLYPH_MAP.get(c, c) for c in s)

_DECODERS = {
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

def fully_decode_payload(payload):
    flag = True
    decode_stack = []
    while flag:
        new_p_0 = payload
        for decoder in _DECODERS:
            old_p_0 = new_p_0
            new_p_1 = _DECODERS[decoder](old_p_0)
            if new_p_1 != old_p_0:
                decode_stack.append((decoder, old_p_0, new_p_1))
                new_p_0 = new_p_1
        if new_p_0 == payload:
            flag = False
        else:
            payload = new_p_0
    return payload, decode_stack
