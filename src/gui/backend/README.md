# LLMShield Backend - Refactored Structure

## Directory Structure

```
backend/
├── app.py                  # Flask API server (routes only)
├── utils.py                # Legacy compatibility layer
├── config/                 # Configuration module
│   ├── __init__.py
│   ├── settings.py         # Environment variables, DVWA config
│   └── prompts.py          # LLM prompts (red team, blue team)
└── services/               # Business logic services
    ├── __init__.py
    ├── llm_service.py      # OpenAI API client
    ├── payload_service.py  # Payload generation using LLM
    ├── defense_service.py  # Defense rule generation using LLM
    └── dvwa_service.py     # DVWA login and attack functions
```

## Module Descriptions

### `config/settings.py`
Contains all application configuration:
- OpenAI API key and model selection
- DVWA base URL, credentials, security level
- Default values for payload count, defense rules

**Usage:**
```python
from config.settings import DVWA_BASE_URL, OPENAI_MODEL
```

### `config/prompts.py`
LLM prompt templates for:
- Red team payload generation
- Blue team defense rule creation

**Usage:**
```python
from config.prompts import RED_TEAM_SYSTEM_PROMPT, get_red_team_user_prompt
```

### `services/llm_service.py`
OpenAI API client wrapper.

**Functions:**
- `chatgpt_completion(messages, model, response_format)` - Send chat completion request

**Usage:**
```python
from services.llm_service import chatgpt_completion

response = chatgpt_completion(
    messages=[{"role": "user", "content": "Hello"}],
    model="gpt-4o"
)
```

### `services/payload_service.py`
Payload generation service using LLM.

**Functions:**
- `generate_payloads_from_domain_waf_info(waf_info, attack_type, num_of_payloads)` - Generate attack payloads

**Usage:**
```python
from services.payload_service import generate_payloads_from_domain_waf_info

result = generate_payloads_from_domain_waf_info(
    waf_info={"firewall": "ModSecurity"},
    attack_type="xss_dom",
    num_of_payloads=5
)
payloads = json.loads(result["choices"][0]["message"]["content"])["items"]
```

### `services/defense_service.py`
Defense rule generation service using LLM.

**Functions:**
- `generate_defend_rules_and_instructions(waf_info, bypassed_payloads, bypassed_instructions)` - Generate ModSecurity rules

**Usage:**
```python
from services.defense_service import generate_defend_rules_and_instructions

result = generate_defend_rules_and_instructions(
    waf_info={"firewall": "ModSecurity"},
    bypassed_payloads=["<script>alert(1)</script>"],
    bypassed_instructions=["Basic XSS payload"]
)
rules = json.loads(result["choices"][0]["message"]["content"])["items"]
```

### `services/dvwa_service.py`
DVWA integration for attack execution.

**Functions:**
- `loginDVWA()` - Login and return PHPSESSID
- `attack_xss_dom(payload, session_id)` - Execute XSS DOM attack
- `attack_xss_reflected(payload, session_id)` - Execute XSS Reflected attack
- `attack_xss_stored(payload, session_id)` - Execute XSS Stored attack
- `attack_sql_injection(payload, session_id)` - Execute SQL Injection attack
- `attack_sql_injection_blind(payload, session_id)` - Execute Blind SQL Injection attack

All attack functions return: `{"status_code": int, "blocked": bool}`

**Usage:**
```python
from services.dvwa_service import loginDVWA, attack_xss_dom

session_id = loginDVWA()
result = attack_xss_dom("<script>alert(1)</script>", session_id)
print(f"Blocked: {result['blocked']}, Status: {result['status_code']}")
```

### `utils.py` - Legacy Compatibility
Re-exports all functions from services for backwards compatibility.

**Existing code continues to work:**
```python
# Old code (still works)
from utils import loginDVWA, attack_xss_dom

# New code (recommended)
from services.dvwa_service import loginDVWA, attack_xss_dom
```

## Backwards Compatibility

All existing code (`app.py`, CLI) continues to work without changes because `utils.py` re-exports all functions from the new modules.

## Benefits of Refactoring

1. **Separation of Concerns**: Configuration, prompts, and business logic are separated
2. **Maintainability**: Easier to find and modify specific functionality
3. **Testability**: Each service can be tested independently
4. **Extensibility**: Easy to add new attack types or LLM models
5. **Documentation**: Clear module boundaries with specific responsibilities

## Adding New Attack Types

1. **Add attack function to `services/dvwa_service.py`:**
```python
def attack_new_type(payload, session_id):
    url = f"{DVWA_BASE_URL}/vulnerabilities/new/?param={payload}"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return {
        "status_code": response.status_code,
        "blocked": _check_blocked(response)
    }
```

2. **Export from `services/__init__.py`:**
```python
from .dvwa_service import (
    ...
    attack_new_type
)
```

3. **Update `utils.py` for backwards compatibility:**
```python
from services import (
    ...
    attack_new_type
)

__all__ = [
    ...
    'attack_new_type'
]
```

## Configuration Changes

To change DVWA domain, credentials, or OpenAI model, edit `config/settings.py`:

```python
DVWA_BASE_URL = "http://your-domain.com"
DVWA_USERNAME = "your-username"
DVWA_PASSWORD = "your-password"
OPENAI_MODEL = "gpt-3.5-turbo"  # For faster/cheaper generation
```

## Environment Variables

Create `.env` file in project root:

```env
OPENAI_API_KEY=sk-proj-xxxxx
```

Loaded by `config/settings.py` using `python-dotenv`.

## Testing

```bash
# Test imports
cd /Users/quangnguyen/Desktop/LLM4WAF/src/gui/backend
python3 -c "from utils import loginDVWA; print('✅ Import successful')"

# Test API server
python3 app.py

# Test CLI (uses same backend)
cd ../..
python3 src/cli/main.py detect -d modsec.llmshield.click
```

## Migration Guide

**No migration needed!** Existing code continues to work. However, for new code:

### Before (old style)
```python
from utils import generate_payloads_from_domain_waf_info
from utils import loginDVWA, attack_xss_dom
```

### After (new style, recommended)
```python
from services.payload_service import generate_payloads_from_domain_waf_info
from services.dvwa_service import loginDVWA, attack_xss_dom
from config.settings import DVWA_BASE_URL
```

---

**Refactored for maintainability and extensibility**
