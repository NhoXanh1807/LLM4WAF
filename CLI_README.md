# LLMShield CLI - User Guide

## Overview

LLMShield CLI is a powerful command-line interface for automated WAF testing and security assessment. Perfect for CI/CD pipelines, security automation, and penetration testing workflows.

## Features

- **WAF Detection**: Fingerprint web application firewalls using WAFW00F
- **Payload Generation**: AI-powered attack payload creation using GPT-4
- **Automated Testing**: Execute attacks against DVWA and analyze results
- **Defense Rules**: Auto-generate ModSecurity rules for bypassed payloads
- **JSON Output**: Machine-readable output for automation
- **Scriptable**: Easy integration with security tools and workflows

## Installation

### Prerequisites

- Python 3.11+ (Python 3.13 not fully supported)
- OpenAI API Key
- Access to target DVWA instance

### Setup

```bash
cd /Users/quangnguyen/Desktop/LLM4WAF

# Install dependencies
pip install flask flask-cors wafw00f requests python-dotenv openai

# Create .env file with OpenAI API key
cat > .env << EOF
OPENAI_API_KEY=sk-proj-your-key-here
EOF

# Make CLI executable
chmod +x src/cli/main.py
```

## Commands

### 1. `detect` - WAF Detection

Fingerprint the WAF protecting a target domain.

**Syntax:**
```bash
python src/cli/main.py detect -d <domain>
```

**Example:**
```bash
python src/cli/main.py detect -d modsec.llmshield.click
```

**Output:**
```
[*] Detecting WAF on https://modsec.llmshield.click...
[+] WAF: {
  "detected": true,
  "firewall": "ModSecurity",
  "manufacturer": "Trustwave"
}
```

---

### 2. `generate` - Payload Generation

Generate attack payloads without testing them.

**Syntax:**
```bash
python src/cli/main.py generate -d <domain> -t <attack_type> [-n <num_payloads>]
```

**Parameters:**
- `-d, --domain`: Target domain (required)
- `-t, --type`: Attack type (required)
  - `xss_dom` - XSS DOM-Based
  - `xss_reflected` - XSS Reflected
  - `xss_stored` - XSS Stored
  - `sql_injection` - SQL Injection
  - `sql_injection_blind` - Blind SQL Injection
- `-n, --num`: Number of payloads (default: 5, max: 20)

**Example:**
```bash
python src/cli/main.py generate -d modsec.llmshield.click -t xss_dom -n 10
```

**Output:**
```
[*] Detecting WAF on https://modsec.llmshield.click...
[+] WAF: {"detected": true, "firewall": "ModSecurity"}
[*] Generating 10 xss_dom payloads...
[+] Generated 10 payloads

  [1] <script>alert(String.fromCharCode(88,83,83))</script>
  [2] <img src=x onerror=alert`1`>
  [3] <svg/onload=alert(1)>
  ...
```

---

### 3. `attack` - Full Attack Workflow

Complete attack workflow: detect WAF → generate payloads → test → generate defense rules.

**Syntax:**
```bash
python src/cli/main.py attack -d <domain> -t <attack_type> [-n <num_payloads>] [-o <output_file>]
```

**Parameters:**
- `-d, --domain`: Target domain (required)
- `-t, --type`: Attack type (required)
- `-n, --num`: Number of payloads (default: 5)
- `-o, --output`: Save results to JSON file (optional)

**Example:**
```bash
python src/cli/main.py attack -d modsec.llmshield.click -t sql_injection -n 5 -o results.json
```

**Output:**
```
[*] Detecting WAF on https://modsec.llmshield.click...
[+] WAF: {"detected": true, "firewall": "ModSecurity"}

[*] Generating 5 sql_injection payloads...
[+] Generated 5 payloads

  [1] ' OR '1'='1
  [2] 1' UNION SELECT NULL--
  [3] 1' AND 1=1--
  [4] ' OR 1=1#
  [5] 1' WAITFOR DELAY '0:0:5'--

[*] Testing payloads...
  [1] BLOCKED - ' OR '1'='1
  [2] BLOCKED - 1' UNION SELECT NULL--
  [3] BYPASSED - 1' AND 1=1--
  [4] BLOCKED - ' OR 1=1#
  [5] BLOCKED - 1' WAITFOR DELAY '0:0:5'--

[*] Generating defense rules for 1 bypassed payloads...

============================================================
Rule 1:
============================================================
SecRule ARGS "@rx (?i)and\s+\d+=\d+" \
    "id:900001,\
    phase:2,\
    block,\
    log,\
    msg:'SQL Injection - Tautology Detected',\
    severity:'CRITICAL'"

Implementation:
Add this rule to your ModSecurity configuration file (e.g., /etc/modsecurity/custom_rules.conf).
Reload Apache/Nginx after adding the rule.

[+] Saved to results.json
[+] Done!
```

## JSON Output Format

When using `-o` flag, results are saved in JSON format:

```json
{
  "domain": "https://modsec.llmshield.click",
  "waf_info": {
    "detected": true,
    "firewall": "ModSecurity",
    "manufacturer": "Trustwave"
  },
  "results": [
    {
      "payload": "' OR '1'='1",
      "attack_type": "sql_injection",
      "instruction": "Basic SQL injection tautology",
      "bypassed": false,
      "status_code": 403
    },
    {
      "payload": "1' AND 1=1--",
      "attack_type": "sql_injection",
      "instruction": "Conditional SQL injection",
      "bypassed": true,
      "status_code": 200
    }
  ],
  "defense_rules": [
    {
      "rule": "SecRule ARGS \"@rx (?i)and\\s+\\d+=\\d+\" ...",
      "instructions": "Add this rule to your ModSecurity configuration..."
    }
  ]
}
```

## Attack Types Explained

### XSS DOM-Based (`xss_dom`)
- **Target**: Client-side JavaScript vulnerabilities
- **DVWA URL**: `/vulnerabilities/xss_d/?default=<payload>`
- **Example**: `<svg/onload=alert(1)>`

### XSS Reflected (`xss_reflected`)
- **Target**: Server-reflected input vulnerabilities
- **DVWA URL**: `/vulnerabilities/xss_r/?name=<payload>`
- **Example**: `<script>alert(document.cookie)</script>`

### XSS Stored (`xss_stored`)
- **Target**: Persistent storage vulnerabilities
- **DVWA URL**: `/vulnerabilities/xss_s/`
- **Example**: `<img src=x onerror=alert(1)>`

### SQL Injection (`sql_injection`)
- **Target**: Database query manipulation
- **DVWA URL**: `/vulnerabilities/sqli/?id=<payload>`
- **Example**: `' UNION SELECT user,password FROM users--`

### Blind SQL Injection (`sql_injection_blind`)
- **Target**: Time-based SQL injection
- **DVWA URL**: `/vulnerabilities/sqli_blind/?id=<payload>`
- **Example**: `1' AND IF(1=1,SLEEP(5),0)--`

## Usage Examples

### Example 1: Quick WAF Detection
```bash
python src/cli/main.py detect -d example.com
```

### Example 2: Generate XSS Payloads
```bash
python src/cli/main.py generate -d target.com -t xss_reflected -n 10
```

### Example 3: Full Attack with JSON Export
```bash
python src/cli/main.py attack \
  -d modsec.llmshield.click \
  -t sql_injection \
  -n 15 \
  -o sqli_results.json
```

### Example 4: Test All Attack Types (Bash Loop)
```bash
for type in xss_dom xss_reflected xss_stored sql_injection sql_injection_blind; do
  python src/cli/main.py attack -d target.com -t $type -n 5 -o results_$type.json
done
```

### Example 5: CI/CD Integration
```bash
#!/bin/bash
# Run WAF security test in CI pipeline

DOMAIN="staging.example.com"
RESULTS_DIR="./waf_tests"
mkdir -p $RESULTS_DIR

# Test each attack vector
for attack in xss_dom sql_injection; do
  echo "Testing $attack..."
  python src/cli/main.py attack \
    -d $DOMAIN \
    -t $attack \
    -n 10 \
    -o $RESULTS_DIR/${attack}_$(date +%Y%m%d).json
done

# Check if any payloads bypassed
if grep -q '"bypassed": true' $RESULTS_DIR/*.json; then
  echo "CRITICAL: WAF bypass detected!"
  exit 1
fi
```

## Automation & Scripting

### Parse JSON Results with jq

**Count bypassed payloads:**
```bash
jq '[.results[] | select(.bypassed == true)] | length' results.json
```

**Extract all bypassed payloads:**
```bash
jq '.results[] | select(.bypassed == true) | .payload' results.json
```

**Get defense rules:**
```bash
jq '.defense_rules[].rule' results.json
```

### Python Automation Script

```python
import subprocess
import json

# Run attack
result = subprocess.run([
    'python', 'src/cli/main.py', 'attack',
    '-d', 'target.com',
    '-t', 'xss_dom',
    '-n', '10',
    '-o', 'results.json'
], capture_output=True)

# Parse results
with open('results.json') as f:
    data = json.load(f)

# Alert if bypasses found
bypassed = [r for r in data['results'] if r['bypassed']]
if bypassed:
    print(f"ALERT: {len(bypassed)} payloads bypassed WAF!")
    for payload in bypassed:
        print(f"  - {payload['payload']}")
```

## Troubleshooting

### Error: "OPENAI_API_KEY not found"

**Solution:**
```bash
# Verify .env file exists
cat .env

# Should contain:
OPENAI_API_KEY=sk-proj-xxxxx

# Set environment variable directly (temporary)
export OPENAI_API_KEY="sk-proj-xxxxx"
```

### Error: "DVWA Connection Failed"

**Causes:**
- DVWA not running
- Incorrect domain in `src/gui/backend/utils.py`
- Network/firewall blocking access

**Solution:**
```bash
# Test DVWA connectivity
curl -I http://modsec.llmshield.click/login.php

# Check domain in utils.py matches your setup
grep "modsec.llmshield.click" src/gui/backend/utils.py

# Update domain if needed
sed -i 's/modsec.llmshield.click/your-domain.com/g' src/gui/backend/utils.py
```

### Error: "Module not found"

**Solution:**
```bash
# Ensure you're in project root
cd /Users/quangnguyen/Desktop/LLM4WAF

# Install dependencies
pip install -r requirements.txt

# Run with python3 explicitly
python3 src/cli/main.py detect -d target.com
```

### Slow Payload Generation

**Causes:**
- OpenAI API rate limits
- Large payload count (>10)

**Solution:**
```bash
# Reduce payload count
python src/cli/main.py attack -d target.com -t xss_dom -n 3

# Use faster model (edit utils.py)
# Change "gpt-4o" to "gpt-3.5-turbo" for faster generation
```

## Performance

| Operation | Time | Notes |
|-----------|------|-------|
| WAF Detection | 2-5s | Depends on network latency |
| Payload Generation (5) | 10-30s | OpenAI API call |
| Payload Testing (5) | 5-15s | 1-3s per payload |
| Defense Rule Gen | 15-30s | OpenAI API call |
| **Full Attack (5 payloads)** | **30-80s** | Total workflow |

## Environment Variables

Create `.env` file in project root:

```env
# Required
OPENAI_API_KEY=sk-proj-xxxxx

# Optional (for GUI compatibility)
REACT_APP_API_URL=http://localhost:5000/api
```

## Security Notes

**WARNING**: This tool is for authorized security testing only.

- Only use against systems you own or have written permission to test
- DVWA should run in an isolated environment (not production)
- Do not use on third-party websites without authorization
- Unauthorized testing may violate computer fraud laws
- Keep OpenAI API key secret (add `.env` to `.gitignore`)

## Advanced Usage

### Custom DVWA Domain

Edit `src/gui/backend/utils.py`:

```python
# Line 144-168: Update URLs
def attack_xss_dom(payload, session_id):
    url = f"http://YOUR-DOMAIN/vulnerabilities/xss_d/?default={payload}"
    ...
```

### Extend Attack Types

Add new attack function in `utils.py`:

```python
def attack_command_injection(payload, session_id):
    url = f"http://dvwa/vulnerabilities/exec/?ip={payload}"
    response = requests.get(url, cookies={"PHPSESSID": session_id})
    return {
        "status_code": response.status_code,
        "blocked": "ModSecurity" in response.text or response.status_code == 403
    }
```

Update `main.py`:

```python
# Line 56-62: Add to attack_funcs dict
attack_funcs = {
    ...
    "command_injection": utils.attack_command_injection,
}

# Line 122: Add to choices
choices=['xss_dom', ..., 'command_injection']
```

## Comparison: CLI vs GUI

| Feature | CLI | GUI |
|---------|-----|-----|
| Attack Testing | ✅ | ✅ |
| Payload Generation | ✅ | ✅ |
| Defense Rules | ✅ | ✅ |
| Retest Function | ❌ | ✅ |
| Dark/Light Theme | N/A | ✅ |
| JSON Export | ✅ | ✅ |
| Automation | ✅ | ❌ |
| CI/CD Integration | ✅ | ❌ |
| Interactive UI | ❌ | ✅ |
| Scriptable | ✅ | ❌ |

**Use CLI for:** Automation, CI/CD, scripting, headless servers
**Use GUI for:** Interactive testing, visual analysis, retest functionality

## Support

For issues or questions:
- GitHub Issues: `https://github.com/yourusername/LLMShield/issues`
- GUI Documentation: See `GUI_README.md`
- Project Overview: See `INSTRUCTIONS.md`

---

**Built with Python + OpenAI GPT-4 + WAFW00F**
