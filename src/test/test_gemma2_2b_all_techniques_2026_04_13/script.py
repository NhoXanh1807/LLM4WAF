

with open(r'K:\Workspace\bku\LLM4WAF\src\test\test_gemma2_2b_all_techniques_2026_04_13\logs\2026-04-13_22-14-32\ModSecurity_xss_dom.txt',
        'r', encoding='utf-8') as f:
    lines = f.readlines()
    print(f"Total lines: {len(lines)}")