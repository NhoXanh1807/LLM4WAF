

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../core")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.stdout.reconfigure(encoding='utf-8')
import json
from utils import WAF_DVWA_URLS

waf_attack_type_mapping = {
    "ModSecurity": "xss_stored",
    "Naxsi":"xss_dom",
    "Cloudflare":"sql_injection_blind",
    "AWS":"sql_injection",
}
data = {
    "generated_rules": {},
    "final_rules": {}
}
for exclude in [
    'clustering',
    'rag_val_retry_refine',
    'none'
]:
    for waf_name in WAF_DVWA_URLS:
        attack_type = waf_attack_type_mapping.get(waf_name)
        phase = "PHASE_3" if waf_name != "Cloudflare" else "PHASE_1"
        file = os.path.join(os.path.dirname(__file__), "2_after_defend", f"defend.exclude.{exclude}.{waf_name}.{attack_type}.{phase}.json")
        with open(file, "r", encoding="utf-8") as f:
            defend_results = json.load(f)
        
        if exclude == 'rag_val_retry_refine' or exclude == 'none':
            final_rules = [item.get("rule", "") for item in defend_results["data"]["final_rules"]]
            if waf_name not in data["final_rules"]:
                data["final_rules"][waf_name] = {}
            data["final_rules"][waf_name][exclude] = final_rules
        
        if exclude == 'clustering' or exclude == 'none':
            generated_rules = [item.get("rule", "") for item in defend_results["data"]["generated_rules"]]
            if waf_name not in data["generated_rules"]:
                data["generated_rules"][waf_name] = {}
            data["generated_rules"][waf_name][exclude] = generated_rules

output = os.path.join(os.path.dirname(__file__), "defend_pipeline_comparison.json")
print(output)
with open(output, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=4)

# generated_rules_with_clustering = """

# Generated rules for ModSecurity - SQL Injection:

# SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|XML:/*|REQUEST_BODY "@rx (?i)(?:<(?:script|svg|img|iframe|body|a)\b[^>]{0,256}\b(?:on[a-z]{3,32}\s*=|src\s*=\s*['\"]?\s*javascript\s*:|href\s*=\s*['\"]?\s*javascript\s*:)|(?:^|[\s'\"`=:(;,])javascript\s*:)" "id:900001,phase:2,block,status:403,severity:CRITICAL,msg:'XSS: dangerous tag/event/javascript URI after normalization',t:none,t:urlDecodeUni,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:htmlEntityDecode,t:removeNulls,t:compressWhitespace,t:lowercase"
# SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|XML:/*|REQUEST_BODY "@rx (?i)<\s*script\b[^>]*>|<\s*/\s*script\s*>|<\s*svg\b[^>]*\bon[a-z]{3,32}\s*=|<\s*img\b[^>]*\bonerror\s*=|<\s*body\b[^>]*\bonload\s*=|<\s*iframe\b[^>]*\bsrc\s*=\s*['\"]?\s*javascript\s*:|<\s*a\b[^>]*\bhref\s*=\s*['\"]?\s*javascript\s*:" "id:900002,phase:2,block,status:403,severity:CRITICAL,msg:'XSS: raw high-confidence tag pattern',t:none,t:urlDecodeUni,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase"
# SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|XML:/*|REQUEST_BODY "@rx (?i)(?:java\s*/\*.*?\*/\s*script|java\s*script)\s*:|(?:on[a-z]{3,32})\s*=\s*['\"]?\s*(?:alert|confirm|prompt|eval|settimeout|setinterval|location\s*=)" "id:900003,phase:2,block,status:403,severity:CRITICAL,msg:'XSS: obfuscated javascript scheme or event handler execution sink',t:none,t:urlDecodeUni,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:removeComments,t:compressWhitespace,t:lowercase"
# SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|XML:/*|REQUEST_BODY "@rx (?i)(?:%25(?:2[0-9a-f]|3[cCeE]|4[67]|5[bBdD]|[0-9a-f]{2})){4,}|(?:&#(?:x0*3[cCeE]|0*47|0*60|0*62|0*34|0*39|\d{2,5});){2,}" "id:900004,phase:2,deny,status:403,severity:ERROR,msg:'Anomaly: excessive multi-layer encoding consistent with XSS obfuscation',t:none,t:urlDecodeUni,t:lowercase"
# SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|XML:/*|REQUEST_BODY "@rx (?i)(?:alert|confirm|prompt)\s*\(\s*\d{0,4}\s*\)|location\s*=\s*['\"]?\s*javascript\s*:" "id:900005,phase:2,deny,status:403,severity:ERROR,msg:'XSS: execution primitive observed after decoding',t:none,t:urlDecodeUni,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:removeComments,t:compressWhitespace,t:lowercase"
# SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|XML:/*|REQUEST_BODY "@rx (?i)(?:<\s*[^>]{0,32}\b(?:script|svg|img|iframe|body|a)\b|(?:onload|onerror|onclick|onmouseover|onfocus|onbegin)\s*=|(?:src|href)\s*=\s*['\"]?\s*javascript\s*:).*(?:alert|confirm|prompt|location\s*=)" "id:900006,phase:2,deny,status:403,severity:CRITICAL,msg:'XSS: correlated markup plus execution pattern',t:none,t:urlDecodeUni,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:htmlEntityDecode,t:removeNulls,t:compressWhitespace,t:lowercase"
# SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|XML:/*|REQUEST_BODY "@rx (?i)(?:onclick|onload|onerror|onmouseover|onfocus|onbegin)%3d|(?:onclick|onload|onerror|onmouseover|onfocus|onbegin)\s*=|(?:<|&lt;|&#60;)\s*(?:img|svg|iframe|script|body|a)\b" "id:900007,phase:2,deny,status:403,severity:ERROR,msg:'XSS: encoded attribute or tag opener',t:none,t:urlDecodeUni,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase"
# SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|XML:/*|REQUEST_BODY "@rx (?i)[\x{0080}-\x{FFFF}]{4,}.*(?:%25|&#)|(?:%25|&#).*[\x{0080}-\x{FFFF}]{4,}" "id:900008,phase:2,log,pass,severity:NOTICE,msg:'Anomaly: mixed Unicode and encoded data requiring review',t:none,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:lowercase"
# SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|XML:/*|REQUEST_BODY "@rx (?i)(?:<\s*a\b[^>]{0,256}\bhref\s*=\s*['\"]?\s*javascript\s*:)(?!void\s*\(\s*0\s*\))|(?:<\s*iframe\b[^>]{0,256}\bsrc\s*=\s*['\"]?\s*javascript\s*:)" "id:900009,phase:2,deny,status:403,severity:CRITICAL,msg:'XSS: active javascript URI in anchor or iframe',t:none,t:urlDecodeUni,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:compressWhitespace,t:lowercase"
# SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|XML:/*|REQUEST_BODY "@rx (?i)<\s*img\b[^>]{0,256}\bsrc\s*=\s*[^>]{0,128}\bonerror\s*=|<\s*svg\b[^>]{0,256}\bonload\s*=|<\s*body\b[^>]{0,256}\bonload\s*=" "id:900010,phase:2,deny,status:403,severity:CRITICAL,msg:'XSS: auto-executing event handler in common gadget tag',t:none,t:urlDecodeUni,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:compressWhitespace,t:lowercase"


# Generated rules for Naxsi - SQL Injection:

# MainRule "rx:(?i)(?:%25|%2[0-9a-f]|&#(?:x0*25|0*37|0*47|0*60|0*62);|[％﹪]).{0,24}(?:%25|%2[0-9a-f]|&#(?:x0*3c|0*60);|[＜<]).{0,24}(?:script|svg|img|iframe|body)" "msg:multi-layer encoded tag prelude" "mz:URL|ARGS|BODY" "s:$XSS:8,$ENCODED:4" id:110001;
# MainRule "rx:(?i)(?:%25|%2[0-9a-f]|&#(?:x0*3c|0*60|0*47|0*62);|[＜＞／/=]).{0,32}(?:script|svg|img|iframe|body)(?:.{0,32}(?:on[a-z]{3,20}|src|href))?" "msg:encoded html tag with executable context" "mz:URL|ARGS|BODY" "s:$XSS:8,$HTML:4" id:110002;
# MainRule "rx:(?i)(?:<|[＜]|%3c|%253c|&#0*60;|&#x0*3c;).{0,32}(?:script|svg|img|iframe|body)" "msg:tag start for active content" "mz:URL|ARGS|BODY" "s:$XSS:8,$HTML:4" id:110003;
# MainRule "rx:(?i)(?:script|svg|img|iframe|body).{0,40}(?:>|[＞]|%3e|%253e|&#0*62;|&#x0*3e;)" "msg:tag end for active content" "mz:URL|ARGS|BODY" "s:$XSS:8,$HTML:4" id:110004;
# MainRule "rx:(?i)(?:on[a-z]{3,20})\s*(?:=|[＝]|%3d|%253d|&#0*61;|&#x0*3d;)" "msg:event handler assignment" "mz:URL|ARGS|BODY" "s:$XSS:8,$ATTR:4" id:110005;
# MainRule "rx:(?i)(?:onload|onerror|onclick|onmouseover|onfocus|onanimationstart|onbegin|onreadystatechange|ontextend|onstart)\b" "msg:dangerous event handler keyword" "mz:URL|ARGS|BODY" "s:$XSS:4,$ATTR:4" id:110006;
# MainRule "rx:(?i)(?:src|href)\s*(?:=|[＝]|%3d|%253d|&#0*61;|&#x0*3d;)\s*(?:javascript|data)\s*(?::|[：]|%3a|%253a|&#0*58;|&#x0*3a;)" "msg:active uri scheme in attribute" "mz:URL|ARGS|BODY" "s:$XSS:8,$URI:4" id:110007;
# MainRule "rx:(?i)javascript\s*(?::|[：]|%3a|%253a|&#0*58;|&#x0*3a;)" "msg:javascript scheme token" "mz:URL|ARGS|BODY" "s:$XSS:8,$URI:4" id:110008;
# MainRule "rx:(?i)alert\s*(?:\(|[（]|%28|%2528|&#0*40;|&#x0*28;).{0,8}(?:\)|[）]|%29|%2529|&#0*41;|&#x0*29;)" "msg:javascript execution primitive alert" "mz:URL|ARGS|BODY" "s:$XSS:8,$JS:4" id:110009;
# MainRule "rx:(?i)(?:<|[＜]|%3c|%253c|&#0*60;|&#x0*3c;).{0,32}(?:script).{0,64}(?:alert|confirm|prompt|eval|Function)" "msg:script tag with execution sink" "mz:URL|ARGS|BODY" "s:$XSS:8,$JS:4" id:110010;
# MainRule "rx:(?i)(?:<|[＜]|%3c|%253c|&#0*60;|&#x0*3c;).{0,32}(?:svg|img|iframe|body).{0,96}(?:on[a-z]{3,20}|src|href|xlink:href)" "msg:active non-script html tag abuse" "mz:URL|ARGS|BODY" "s:$XSS:8,$HTML:4" id:110011;
# MainRule "rx:(?i)(?:%25[0-9a-f]{2}){3,}" "msg:excessive percent-encoding sequence" "mz:URL|ARGS|BODY" "s:$ENCODED:4" id:110012;
# MainRule "rx:(?i)(?:[％﹪][0-9０-９A-Fa-fＡ-Ｆａ-ｆ]{2}){3,}" "msg:fullwidth percent-encoding sequence" "mz:URL|ARGS|BODY" "s:$ENCODED:4" id:110013;
# MainRule "rx:(?i)(?:&#(?:x[0-9a-f]{2,5}|[0-9]{2,5});){2,}" "msg:stacked html entity encoding" "mz:URL|ARGS|BODY" "s:$ENCODED:4" id:110014;
# MainRule "rx:(?i)(?:script|svg|img|iframe|javascript|onload|onerror|onclick|alert)" "msg:xss keyword baseline" "mz:URL|ARGS|BODY" "s:$XSS:2" id:110015;
# MainRule "rx:(?i)(?:%3c|%253c|&#0*60;|&#x0*3c;|[＜<]).{0,12}(?:%2f|%252f|&#0*47;|&#x0*2f;|[／/])?.{0,12}(?:script|svg|img|iframe|body)" "msg:encoded tag opener with optional slash" "mz:URL|ARGS|BODY" "s:$XSS:8,$HTML:4" id:110016;
# MainRule "rx:(?i)(?:%2f|%252f|&#0*47;|&#x0*2f;|[／/]).{0,8}(?:script|svg|img|iframe|body).{0,24}(?:%3e|%253e|&#0*62;|&#x0*3e;|[＞>])" "msg:encoded closing or self-closing active tag fragment" "mz:URL|ARGS|BODY" "s:$XSS:6,$HTML:4" id:110017;
# MainRule "rx:(?i)(?:on[a-z]{3,20}|src|href).{0,8}(?:%25(?:3d|3a)|%3d|%3a|=|:|[＝：]).{0,40}(?:javascript|alert|data|[<＜]|%3c|%253c|&#0*60;|&#x0*3c;)" "msg:encoded attribute leading to executable content" "mz:URL|ARGS|BODY" "s:$XSS:8,$ATTR:4,$URI:4" id:110018;
# CheckRule "$XSS >= 8" BLOCK;
# CheckRule "$XSS >= 6 && $ENCODED >= 4" BLOCK;
# CheckRule "$HTML >= 4 && $ATTR >= 4" BLOCK;
# CheckRule "$URI >= 4 && $JS >= 4" BLOCK;
# CheckRule "$ENCODED >= 8" CHALLENGE;

# Generated rules for Cloudflare - SQL Injection:

# (http.request.uri contains "%2527" and http.request.uri contains "union" and http.request.uri contains "select") or (http.request.body.raw contains "%2527" and http.request.body.raw contains "union" and http.request.body.raw contains "select") or (http.request.uri contains "%27" and http.request.uri contains "union" and http.request.uri contains "select") or (http.request.body.raw contains "%27" and http.request.body.raw contains "union" and http.request.body.raw contains "select")
# (http.request.uri contains "%2527" and http.request.uri contains "UNION" and http.request.uri contains "SELECT") or (http.request.body.raw contains "%2527" and http.request.body.raw contains "UNION" and http.request.body.raw contains "SELECT") or (http.request.uri contains "%27" and http.request.uri contains "UNION" and http.request.uri contains "SELECT") or (http.request.body.raw contains "%27" and http.request.body.raw contains "UNION" and http.request.body.raw contains "SELECT")
# (http.request.uri contains "User%2528%2529" and http.request.uri contains "select") or (http.request.body.raw contains "User%2528%2529" and http.request.body.raw contains "select") or (http.request.uri contains "user()" and http.request.uri contains "select") or (http.request.body.raw contains "user()" and http.request.body.raw contains "select") or (http.request.uri contains "version%2528%2529" and http.request.uri contains "select") or (http.request.body.raw contains "version%2528%2529" and http.request.body.raw contains "select")
# (http.request.uri contains "%2520or%25201%253d1") or (http.request.body.raw contains "%2520or%25201%253d1") or (http.request.uri contains "%20or%201%3d1") or (http.request.body.raw contains "%20or%201%3d1") or (http.request.uri contains " or 1=1") or (http.request.body.raw contains " or 1=1") or (http.request.uri contains "%2509or%25091%253d1") or (http.request.body.raw contains "%2509or%25091%253d1")
# (http.request.uri contains "%2527%252b--") or (http.request.body.raw contains "%2527%252b--") or (http.request.uri contains "%2527%2520--") or (http.request.body.raw contains "%2527%2520--") or (http.request.uri contains "%2527%252509--") or (http.request.body.raw contains "%2527%252509--") or (http.request.uri contains "'+--") or (http.request.body.raw contains "'+--") or (http.request.uri contains "' --") or (http.request.body.raw contains "' --")
# (http.request.uri contains "admin%2527") or (http.request.body.raw contains "admin%2527") or (http.request.uri contains "admin'") or (http.request.body.raw contains "admin'")
# (http.request.uri contains "sleep%2528") or (http.request.body.raw contains "sleep%2528") or (http.request.uri contains "SLEEP%2528") or (http.request.body.raw contains "SLEEP%2528") or (http.request.uri contains "sleep(") or (http.request.body.raw contains "sleep(")
# (http.request.uri contains "updatexml%2528") or (http.request.body.raw contains "updatexml%2528") or (http.request.uri contains "UPDATEXML%2528") or (http.request.body.raw contains "UPDATEXML%2528") or (http.request.uri contains "updatexml(") or (http.request.body.raw contains "updatexml(") or (http.request.uri contains "concat%2528") and (http.request.uri contains "version%2528")) or ((http.request.body.raw contains "concat%2528") and (http.request.body.raw contains "version%2528"))
# (http.request.uri contains "%252f%252a") or (http.request.body.raw contains "%252f%252a") or (http.request.uri contains "%2f%2a") or (http.request.body.raw contains "%2f%2a") or (http.request.uri contains "/*!" ) or (http.request.body.raw contains "/*!" ) or (http.request.uri contains "/**/") or (http.request.body.raw contains "/**/")
# (http.request.uri contains "%2525") or (http.request.body.raw contains "%2525") or (http.request.uri contains "%25ef%25") or (http.request.body.raw contains "%25ef%25")
# (http.request.uri contains "%26%2347%3b") or (http.request.body.raw contains "%26%2347%3b") or (http.request.uri contains "&#47;") or (http.request.body.raw contains "&#47;")
# (http.request.uri contains "%253d1") or (http.request.body.raw contains "%253d1") or (http.request.uri contains "%3d1 --") or (http.request.body.raw contains "%3d1 --") or (http.request.uri contains "=1 --") or (http.request.body.raw contains "=1 --")
# (http.request.uri contains "%253bid%253dadmin") or (http.request.body.raw contains "%253bid%253dadmin") or (http.request.uri contains "id=admin' %2509--") or (http.request.body.raw contains "id=admin' %2509--")
# (http.request.uri contains "partition" and http.request.uri contains "version") or (http.request.body.raw contains "partition" and http.request.body.raw contains "version") or (http.request.uri contains "information_schema") or (http.request.body.raw contains "information_schema")


# Generated rules for AWS - SQL Injection:


# """


# generated_rules_without_clustering = """

# Generated rules for ModSecurity - SQL Injection:

# SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY|XML:/*|REQUEST_HEADERS "@detectXSS" "id:910100,phase:2,deny,status:403,log,auditlog,t:none,t:utf8toUnicode,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,msg:'XSS libinjection detection after multi-layer decoding',logdata:'%{MATCHED_VAR}',tag:'attack-xss',severity:'CRITICAL'"
# SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY|XML:/*|REQUEST_HEADERS "@rx (?i)<\s*(?:script|svg|img|iframe|a)\b[^>]{0,256}>|<\s*/\s*script\b" "id:910101,phase:2,deny,status:403,log,auditlog,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,msg:'Obfuscated HTML tag vector associated with XSS',logdata:'%{TX.0}',tag:'attack-xss',severity:'CRITICAL'"
# SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY|XML:/*|REQUEST_HEADERS "@rx (?i)(?:^|[\s\"'`;\/0-9=\x0b\x09\x0c,\(;-])on[a-z]{3,32}[\s\x0b\x09\x0c,;\(]*=\s*[^\s>]+" "id:910102,phase:2,deny,status:403,log,auditlog,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,msg:'Event handler injection pattern detected',logdata:'%{TX.0}',tag:'attack-xss',severity:'CRITICAL'"
# SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY|XML:/*|REQUEST_HEADERS "@rx (?i)(?:src|href)\s*=\s*[\"'` ]*javascript\s*:|javascript\s*:" "id:910103,phase:2,deny,status:403,log,auditlog,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,msg:'javascript: URI XSS vector detected',logdata:'%{TX.0}',tag:'attack-xss',severity:'CRITICAL'"
# SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY|XML:/*|REQUEST_HEADERS "@rx (?i)%(?:25){2,}|(?:%[0-9a-f]{2}){6,}" "id:910104,phase:2,log,auditlog,pass,capture,t:none,t:lowercase,msg:'Excessive URL-encoding anomaly',logdata:'%{TX.0}',tag:'attack-anomaly',severity:'NOTICE'"
# SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY|XML:/*|REQUEST_HEADERS "@rx (?i)(?:%ef%bc%85|％|%e2%85|%d0|%d1|%d3|%d4|%d5|%d6|%d7|%d8|%d9|%da|%db|%dc|%dd|%de|%df)" "id:910105,phase:2,log,auditlog,pass,capture,t:none,t:urlDecodeUni,t:urlDecodeUni,t:lowercase,msg:'Suspicious mixed Unicode/fullwidth encoding near input',logdata:'%{TX.0}',tag:'attack-anomaly',severity:'WARNING'"
# SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY|XML:/*|REQUEST_HEADERS "@rx (?i)<\s*(?:svg|img|iframe|script|a)\b[^>]{0,256}(?:on[a-z]{3,32}\s*=|(?:src|href)\s*=\s*[\"'` ]*javascript\s*:)[^>]{0,256}>" "id:910106,phase:2,deny,status:403,log,auditlog,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,msg:'High-confidence active XSS HTML element detected',logdata:'%{TX.0}',tag:'attack-xss',severity:'CRITICAL'"
# SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY|XML:/*|REQUEST_HEADERS "@rx (?i)<\s*a\b[^>]{0,256}href\s*=\s*[\"'` ]*javascript\s*:[^>]{0,256}>.*<\s*/\s*a\s*>" "id:910107,phase:2,deny,status:403,log,auditlog,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,t:lowercase,t:compressWhitespace,msg:'Anchor javascript URI XSS payload detected',logdata:'%{TX.0}',tag:'attack-xss',severity:'CRITICAL'"


# Generated rules for Naxsi - SQL Injection:

# MainRule "rx:(?:%25|％25){2,}[0-9a-fA-F％％]{2,}" "msg:multi-layer percent-encoding evasion" "mz:URL|ARGS|BODY|HEADERS" "s:$EVADE:4,$XSS:2" id:120001;
# MainRule "rx:(?:&#(?:x0*3[cC]|0*60);|<(?:\s|/|&#(?:x0*2[fF]|0*47);)*)?(?:s|[\x{0455}\x{0405}])(?:c|[\x{0421}\x{0441}])(?:r|[\x{042f}]?r)(?:i|[\x{0406}\x{0456}\x{2170}])(?:p|[\x{0440}])(?:t|[\x{0422}\x{0442}])\b" "msg:script tag keyword obfuscation" "mz:URL|ARGS|BODY|HEADERS" "s:$XSS:8,$EVADE:2" id:120002;
# MainRule "rx:(?:&#(?:x0*3[cC]|0*60);|<)?\s*(?:s|[\x{0455}\x{0405}])(?:v|[\x{0475}\x{2174}])(?:g|[\x{0261}])\b(?:[^>]{0,256})?(?:onload|onerror)\b" "msg:svg event-handler xss pattern" "mz:URL|ARGS|BODY|HEADERS" "s:$XSS:8,$EVADE:2" id:120003;
# MainRule "rx:(?:&#(?:x0*3[cC]|0*60);|<)?\s*(?:i|[\x{0406}\x{0456}\x{2170}])(?:m|[\x{217f}])(?:g|[\x{0261}])\b(?:[^>]{0,256})?onerror\b" "msg:img onerror xss pattern" "mz:URL|ARGS|BODY|HEADERS" "s:$XSS:8,$EVADE:2" id:120004;
# MainRule "rx:(?:&#(?:x0*3[cC]|0*60);|<)?\s*(?:i|[\x{0406}\x{0456}\x{2170}])(?:f|[\x{04fb}])(?:r|[\x{044f}]?r)(?:a|[\x{0430}])(?:m|[\x{217f}])(?:e|[\x{0435}])\b(?:[^>]{0,256})?(?:src\s*=\s*javascript\s*:|javascript\s*:|on[a-z]{3,16}\s*=)" "msg:iframe javascript uri or handler xss pattern" "mz:URL|ARGS|BODY|HEADERS" "s:$XSS:8,$EVADE:2" id:120005;
# MainRule "rx:on(?:load|error|click|mouseover|focus|animationstart|begin)\s*=|o[nN][a-zA-Z]{3,16}\s*=" "msg:inline event handler indicator" "mz:URL|ARGS|BODY|HEADERS" "s:$XSS:6" id:120006;
# MainRule "rx:javascript\s*:|j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:" "msg:javascript uri indicator" "mz:URL|ARGS|BODY|HEADERS" "s:$XSS:7" id:120007;
# MainRule "rx:(?:alert|confirm|prompt)\s*\(" "msg:javascript execution sink indicator" "mz:URL|ARGS|BODY|HEADERS" "s:$XSS:4" id:120008;
# MainRule "rx:(?:<|&#(?:x0*3[cC]|0*60);)\s*(?:script|svg|img|iframe)\b|(?:&\#47;|/)(?:script|svg|iframe)\b" "msg:html tag injection indicator" "mz:URL|ARGS|BODY|HEADERS" "s:$XSS:6" id:120009;
# CheckRule "$XSS >= 8" BLOCK;
# CheckRule "$EVADE >= 6" LOG;
# CheckRule "$XSS >= 6" LOG;


# Generated rules for Cloudflare - SQL Injection:

# (http.request.uri contains "%2527" and (http.request.uri contains "%2520or%2520" or http.request.uri contains "%2520and%2520" or http.request.uri contains "%252509or%252509" or http.request.uri contains "%252509and%252509" or http.request.uri contains "%253d1" or http.request.uri contains "--" or http.request.uri contains "%252d%252d" or http.request.uri contains "%252f%252a" or http.request.uri contains "%252a%252f" or http.request.uri contains "union" or http.request.uri contains "select" or http.request.uri contains "sleep%2528" or http.request.uri contains "updatexml%2528" or http.request.uri contains "user%2528" or http.request.uri contains "version%2528")) or (http.request.uri contains "%2520or%25201%253d1") or (http.request.uri contains "%252509or%2525091%253d1") or (http.request.uri contains "%2520union%2520select") or (http.request.uri contains "%252f%252a" and http.request.uri contains "union" and http.request.uri contains "select") or (http.request.uri contains "sleep%2528") or (http.request.uri contains "updatexml%2528") or (http.request.uri contains "%253bid%253dadmin") or (http.request.uri contains "admin%2527" and (http.request.uri contains "--" or http.request.uri contains "%252509--" or http.request.uri contains "%2520--")) or (http.request.body.raw contains "%2527" and (http.request.body.raw contains "%2520or%2520" or http.request.body.raw contains "%2520and%2520" or http.request.body.raw contains "%252509or%252509" or http.request.body.raw contains "%252509and%252509" or http.request.body.raw contains "%253d1" or http.request.body.raw contains "--" or http.request.body.raw contains "%252d%252d" or http.request.body.raw contains "%252f%252a" or http.request.body.raw contains "%252a%252f" or http.request.body.raw contains "union" or http.request.body.raw contains "select" or http.request.body.raw contains "sleep%2528" or http.request.body.raw contains "updatexml%2528" or http.request.body.raw contains "user%2528" or http.request.body.raw contains "version%2528")) or (http.request.body.raw contains "%2520or%25201%253d1") or (http.request.body.raw contains "%252509or%2525091%253d1") or (http.request.body.raw contains "%2520union%2520select") or (http.request.body.raw contains "%252f%252a" and http.request.body.raw contains "union" and http.request.body.raw contains "select") or (http.request.body.raw contains "sleep%2528") or (http.request.body.raw contains "updatexml%2528") or (http.request.body.raw contains "%253bid%253dadmin") or (http.request.body.raw contains "admin%2527" and (http.request.body.raw contains "--" or http.request.body.raw contains "%252509--" or http.request.body.raw contains "%2520--")))


# Generated rules for AWS - SQL Injection:

# {"OrStatement":{"Statements":[{"SqliMatchStatement":{"FieldToMatch":{"AllQueryArguments":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}],"SensitivityLevel":"HIGH"}},{"SqliMatchStatement":{"FieldToMatch":{"QueryString":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}],"SensitivityLevel":"HIGH"}},{"SqliMatchStatement":{"FieldToMatch":{"Body":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}],"SensitivityLevel":"HIGH"}}]}}
# {"OrStatement":{"Statements":[{"RegexMatchStatement":{"RegexString":"(?:^|[^a-z0-9_])(admin|or|and)(?:[\\s\\-\\/*%]|$)","FieldToMatch":{"AllQueryArguments":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}]}},{"RegexMatchStatement":{"RegexString":"(?:^|[^a-z0-9_])(admin|or|and)(?:[\\s\\-\\/*%]|$)","FieldToMatch":{"QueryString":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}]}},{"RegexMatchStatement":{"RegexString":"(?:^|[^a-z0-9_])(admin|or|and)(?:[\\s\\-\\/*%]|$)","FieldToMatch":{"Body":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}]}}]}}
# {"OrStatement":{"Statements":[{"RegexMatchStatement":{"RegexString":"(?:^|[^0-9a-z_])1\\s*(?:=|like)\\s*1(?:[^0-9a-z_]|$)|(?:^|[^0-9a-z_])1\\s+or\\s+1\\s*=\\s*1(?:[^0-9a-z_]|$)","FieldToMatch":{"AllQueryArguments":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}]}},{"RegexMatchStatement":{"RegexString":"(?:^|[^0-9a-z_])1\\s*(?:=|like)\\s*1(?:[^0-9a-z_]|$)|(?:^|[^0-9a-z_])1\\s+or\\s+1\\s*=\\s*1(?:[^0-9a-z_]|$)","FieldToMatch":{"QueryString":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}]}},{"RegexMatchStatement":{"RegexString":"(?:^|[^0-9a-z_])1\\s*(?:=|like)\\s*1(?:[^0-9a-z_]|$)|(?:^|[^0-9a-z_])1\\s+or\\s+1\\s*=\\s*1(?:[^0-9a-z_]|$)","FieldToMatch":{"Body":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}]}}]}}
# {"OrStatement":{"Statements":[{"RegexMatchStatement":{"RegexString":"(?:'|%27|%2527|\\bchar\\b).*?(?:--|#|/\\*)|(?:--|/\\*).*?(?:'|%27|%2527)|(?:^|[^a-z0-9_])admin\\s*'(?:\\s|/\\*.*?\\*/)*--","FieldToMatch":{"AllQueryArguments":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}]}},{"RegexMatchStatement":{"RegexString":"(?:'|%27|%2527|\\bchar\\b).*?(?:--|#|/\\*)|(?:--|/\\*).*?(?:'|%27|%2527)|(?:^|[^a-z0-9_])admin\\s*'(?:\\s|/\\*.*?\\*/)*--","FieldToMatch":{"QueryString":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}]}},{"RegexMatchStatement":{"RegexString":"(?:'|%27|%2527|\\bchar\\b).*?(?:--|#|/\\*)|(?:--|/\\*).*?(?:'|%27|%2527)|(?:^|[^a-z0-9_])admin\\s*'(?:\\s|/\\*.*?\\*/)*--","FieldToMatch":{"Body":{}},"TextTransformations":[{"Priority":0,"Type":"URL_DECODE_UNI"},{"Priority":1,"Type":"URL_DECODE_UNI"},{"Priority":2,"Type":"URL_DECODE"},{"Priority":3,"Type":"HTML_ENTITY_DECODE"},{"Priority":4,"Type":"UTF8_TO_UNICODE"},{"Priority":5,"Type":"REPLACE_COMMENTS"},{"Priority":6,"Type":"COMPRESS_WHITE_SPACE"},{"Priority":7,"Type":"LOWERCASE"},{"Priority":8,"Type":"REMOVE_NULLS"}]}}]}}
# {"OrStatement":{"Statements":[{"RegexMatchStatement":{"RegexString":"(?:%25(?:2[0-9a-f]|3[0-9a-f]|5[c-f]|e[0-9a-f])){3,}|(?:%[0-9a-f]{2}){6,}|(?:--){2,}|(?:/\\*.*?\\*/){2,}","FieldToMatch":{"AllQueryArguments":{}},"TextTransformations":[{"Priority":0,"Type":"LOWERCASE"}]}},{"RegexMatchStatement":{"RegexString":"(?:%25(?:2[0-9a-f]|3[0-9a-f]|5[c-f]|e[0-9a-f])){3,}|(?:%[0-9a-f]{2}){6,}|(?:--){2,}|(?:/\\*.*?\\*/){2,}","FieldToMatch":{"QueryString":{}},"TextTransformations":[{"Priority":0,"Type":"LOWERCASE"}]}},{"RegexMatchStatement":{"RegexString":"(?:%25(?:2[0-9a-f]|3[0-9a-f]|5[c-f]|e[0-9a-f])){3,}|(?:%[0-9a-f]{2}){6,}|(?:--){2,}|(?:/\\*.*?\\*/){2,}","FieldToMatch":{"Body":{}},"TextTransformations":[{"Priority":0,"Type":"LOWERCASE"}]}}]}}

# """
