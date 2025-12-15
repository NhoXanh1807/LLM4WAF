# LLMShield - Project Structure & Developer Guide

## Overview

LLMShield is an AI-powered Web Application Firewall testing platform featuring:
- **GUI**: Modern React + Flask web application with dark/light themes
- **CLI**: Command-line interface for automation and CI/CD integration
- **Refactored Architecture**: Modular codebase with clear separation of concerns

## Project Structure

```
LLM4WAF/
├── src/
│   ├── gui/                        # Web Application
│   │   ├── backend/                # Flask API Server
│   │   │   ├── app.py              # API routes (/api/attack, /api/retest, /api/defend)
│   │   │   ├── utils.py            # Legacy compatibility layer (re-exports from services)
│   │   │   ├── config/             # ⭐ Configuration Module
│   │   │   │   ├── __init__.py
│   │   │   │   ├── settings.py     # DVWA config, API keys, defaults
│   │   │   │   └── prompts.py      # LLM prompts (red team, blue team)
│   │   │   ├── services/           # ⭐ Business Logic Services
│   │   │   │   ├── __init__.py
│   │   │   │   ├── llm_service.py      # OpenAI API client
│   │   │   │   ├── payload_service.py  # Payload generation
│   │   │   │   ├── defense_service.py  # Defense rule generation
│   │   │   │   └── dvwa_service.py     # DVWA login & attack execution
│   │   │   └── README.md           # Backend architecture documentation
│   │   └── frontend/               # React Application
│   │       ├── public/
│   │       │   ├── index.html          # HTML template with meta tags
│   │       │   ├── manifest.json       # PWA configuration
│   │       │   └── llmshield.png       # Logo/favicon (500x500)
│   │       ├── src/
│   │       │   ├── App.js              # Main React component (353 lines)
│   │       │   ├── BypassedDataTable.js # Results table component (82 lines)
│   │       │   └── services.js         # API client (26 lines)
│   │       ├── package.json        # Frontend dependencies
│   │       └── tailwind.config.js  # Tailwind CSS with dark mode
│   └── cli/                        # Command-Line Interface
│       └── main.py                 # CLI entry point (detect, generate, attack commands)
├── .env                            # Environment variables (OPENAI_API_KEY)
├── requirements.txt                # Python dependencies
├── GUI_README.md                   # GUI user documentation
├── CLI_README.md                   # CLI user documentation
└── INSTRUCTIONS.md                 # This file (developer guide)
```

---

## Architecture Overview

### 1. Backend (Flask API)

#### **`app.py`** - API Routes (177 lines)

**Purpose:** Handle HTTP requests from frontend/external clients.

**Endpoints:**

| Endpoint | Method | Purpose | Key Logic |
|----------|--------|---------|-----------|
| `/api/attack` | POST | Full attack workflow | Detect WAF → Generate payloads → Test → Auto-generate defense rules |
| `/api/retest` | POST | Retest bypassed payloads | Re-test previously bypassed payloads after WAF updates |
| `/api/defend` | POST | Generate defense rules only | Legacy endpoint (now auto-generated in /api/attack) |

**Flow:**
```
Request → app.py → services → config → Response
```

---

#### **`config/` Module** - Configuration & Prompts

##### **`config/settings.py`** (18 lines)

**Purpose:** Centralized configuration management.

```python
# OpenAI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = "gpt-4o"

# DVWA Configuration
DVWA_BASE_URL = "http://modsec.llmshield.click"
DVWA_USERNAME = "admin"
DVWA_PASSWORD = "password"
DVWA_SECURITY_LEVEL = "low"

# Defaults
DEFAULT_NUM_PAYLOADS = 5
DEFAULT_NUM_DEFENSE_RULES = 3
```

**To Change DVWA Domain:** Edit `DVWA_BASE_URL` in this file.

##### **`config/prompts.py`** (86 lines)

**Purpose:** LLM prompt engineering for payload generation and defense rules.

**Constants:**
- `RED_TEAM_SYSTEM_PROMPT` - Elite red team operator persona
- `BLUE_TEAM_SYSTEM_PROMPT` - Defensive security architect persona

**Functions:**
- `get_red_team_user_prompt(waf_info, attack_type, num_payloads)` - Payload generation prompt
- `get_blue_team_user_prompt(waf_info, bypassed_payloads, bypassed_instructions, num_rules)` - Defense rule prompt

**Customization:** Edit prompts here to change attack/defense strategies.

---

#### **`services/` Module** - Business Logic

##### **`services/llm_service.py`** (35 lines)

**Purpose:** OpenAI API client wrapper.

```python
def chatgpt_completion(messages=[], model=None, response_format=None):
    """
    Send chat completion request to OpenAI API

    Args:
        messages (list): [{"role": "user", "content": "..."}]
        model (str): OpenAI model (default: from settings)
        response_format (dict): JSON schema for structured output

    Returns:
        dict: OpenAI API response
    """
```

##### **`services/payload_service.py`** (76 lines)

**Purpose:** Generate attack payloads using GPT-4.

```python
def generate_payloads_from_domain_waf_info(waf_info, attack_type, num_of_payloads=None):
    """
    Generate payloads using LLM

    Returns:
        {
            "choices": [{
                "message": {
                    "content": "{\"items\": [{\"payload\": \"...\", \"instruction\": \"...\"}]}"
                }
            }]
        }
    """
```

**Process:**
1. Build messages with red team prompt
2. Define JSON schema for output
3. Call OpenAI API
4. Return structured response

##### **`services/defense_service.py`** (79 lines)

**Purpose:** Generate ModSecurity defense rules using GPT-4.

```python
def generate_defend_rules_and_instructions(waf_info, bypassed_payloads, bypassed_instructions):
    """
    Generate defense rules using LLM

    Returns:
        {
            "choices": [{
                "message": {
                    "content": "{\"items\": [{\"rule\": \"...\", \"instructions\": \"...\"}]}"
                }
            }]
        }
    """
```

##### **`services/dvwa_service.py`** (180 lines)

**Purpose:** DVWA integration - login and attack execution.

**Functions:**

```python
def loginDVWA():
    """Login to DVWA, return PHPSESSID"""

def _check_blocked(response):
    """Check if WAF blocked request (internal helper)"""

def attack_xss_dom(payload, session_id):
    """Execute XSS DOM attack → {"status_code": int, "blocked": bool}"""

def attack_xss_reflected(payload, session_id):
    """Execute XSS Reflected attack"""

def attack_xss_stored(payload, session_id):
    """Execute XSS Stored attack (POST request)"""

def attack_sql_injection(payload, session_id):
    """Execute SQL Injection attack"""

def attack_sql_injection_blind(payload, session_id):
    """Execute Blind SQL Injection attack"""
```

**Attack Function Pattern:**
1. Build URL with payload
2. Send HTTP request with session cookies
3. Check response for "ModSecurity" string or 403 status
4. Return `{status_code, blocked}` dict

---

#### **`utils.py`** - Backwards Compatibility (38 lines)

**Purpose:** Re-export all functions from `services/` for legacy code.

```python
from services import (
    chatgpt_completion,
    generate_payloads_from_domain_waf_info,
    generate_defend_rules_and_instructions,
    loginDVWA,
    attack_xss_dom,
    # ... all attack functions
)
```

**Why?** Existing code (`app.py`, CLI) can continue using `from utils import ...` without changes.

**Recommendation:** New code should import directly from services.

---

### 2. Frontend (React Application)

#### **`src/App.js`** - Main Component (353 lines)

**Purpose:** Root component managing all UI state and interactions.

**State:**

```javascript
const [activeTab, setActiveTab] = useState('Attack')      // Red/Blue Team tabs
const [wafInfo, setWafInfo] = useState(null)             // WAF detection results
const [payloads, setPayloads] = useState([])             // Attack payloads + results
const [defenseRules, setDefenseRules] = useState([])     // ModSecurity rules
const [darkMode, setDarkMode] = useState(false)          // Theme toggle (persisted in localStorage)
const [isSubmitting, setIsSubmitting] = useState(false)  // Loading state
const [isRetesting, setIsRetesting] = useState(false)    // Retest loading state
```

**Key Features:**

1. **Dark Mode Persistence** (lines 18-30):
```javascript
useEffect(() => {
  localStorage.setItem('darkMode', JSON.stringify(darkMode))
  document.documentElement.classList.toggle('dark', darkMode)
}, [darkMode])
```

2. **Attack Workflow** (lines 100-120):
```javascript
// Submit form → call API → update state → auto-switch to Defend tab if bypassed
const res = await Services.attack(domain, attackType, numPayloads)
const data = await res.json()
if (data?.payloads?.some(p => p.bypassed === true)) {
  setActiveTab('Defend')  // Auto-switch!
}
```

3. **Retest Functionality** (lines 238-269):
```javascript
// Retest bypassed payloads → update results in-place
const updatedPayloads = payloads.map(p => {
  const retestResult = data.results.find(r => r.payload === p.payload)
  return retestResult ? { ...p, bypassed: retestResult.bypassed } : p
})
```

**UI Structure:**
- Header with logo + theme toggle button
- Tab navigation (Red Team / Blue Team)
- Attack form (dropdown, domain input, payload count)
- Results table (BypassedDataTable component)
- Defense rules table (ModSecurity format)
- Download buttons (WAF info, payloads, instructions as JSON)

---

#### **`src/BypassedDataTable.js`** - Results Table (82 lines)

**Purpose:** Display attack results with color-coded status badges.

**Status Badge System:**

```javascript
const getStatusBadge = (item) => {
  if (item.bypassed === true)
    return <span className="bg-gradient-to-r from-red-500...">⚠️ BYPASSED</span>
  else if (item.bypassed === false && item.status_code)
    return <span className="bg-gradient-to-r from-green-500...">✅ BLOCKED</span>
  return <span className="bg-gray-400...">⏳ PENDING</span>
}
```

**Table Columns:**
1. `#` - Row number
2. `Attack Type` - Badge with attack type
3. `Payload` - Monospace font for payload string
4. `Instructions` - GPT-4 deployment instructions
5. `Status Code` - HTTP response code
6. `Result` - Status badge

**Dark Mode:** Conditional styling based on `darkMode` prop.

---

#### **`src/services.js`** - API Client (26 lines)

**Purpose:** Centralized API communication.

```javascript
const BASE_API_URL = process.env.REACT_APP_API_URL || "http://localhost:5000/api"

export const Services = {
  attack: async (domain, attack_type, num_payloads = 5) => {
    return Call("/attack", "POST", { domain, attack_type, num_payloads })
  },
  defend: async (waf_info, bypassed_payloads, bypassed_instructions) => {
    return Call("/defend", "POST", { waf_info, bypassed_payloads, bypassed_instructions })
  },
  retest: async (bypassed_payloads) => {
    return Call("/retest", "POST", { bypassed_payloads })
  }
}
```

---

#### **`public/` Assets**

- **`index.html`**: HTML template with LLMShield branding, favicon, meta tags
- **`manifest.json`**: PWA config (name: "LLMShield", theme_color: "#EF4444")
- **`llmshield.png`**: Logo (500x500px)

#### **`tailwind.config.js`**

```javascript
module.exports = {
  darkMode: 'class',  // Enable class-based dark mode
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  ...
}
```

---

### 3. CLI Application

#### **`src/cli/main.py`** - CLI Interface (174 lines)

**Purpose:** Scriptable interface for automation, CI/CD, security pipelines.

**Commands:**

```bash
# 1. Detect WAF only
python src/cli/main.py detect -d modsec.llmshield.click

# 2. Generate payloads only
python src/cli/main.py generate -d domain.com -t xss_dom -n 10

# 3. Full attack workflow + JSON output
python src/cli/main.py attack -d domain.com -t sql_injection -n 5 -o results.json
```

**Architecture:**

```python
def main():
    parser = argparse.ArgumentParser(...)
    subparsers = parser.add_subparsers(dest='cmd')

    # Create subcommands: detect, generate, attack
    p_detect = subparsers.add_parser('detect')
    p_gen = subparsers.add_parser('generate')
    p_attack = subparsers.add_parser('attack')

    # Execute based on command
    if args.cmd == 'attack':
        waf = detect_waf(args.domain)
        payloads = generate_payloads(waf, args.type, args.num)
        results = test_payloads(payloads, args.type)
        rules = generate_defense(waf, results)
```

**JSON Output:**
```json
{
  "domain": "https://...",
  "waf_info": {...},
  "results": [{payload, bypassed, status_code, ...}],
  "defense_rules": [{rule, instructions}]
}
```

---

## Data Flow

### GUI Attack Workflow

```
User Input (domain, attack_type, num_payloads)
    ↓
Frontend: Services.attack() → POST /api/attack
    ↓
Backend app.py:
    1. Detect WAF (WAFW00F library)
    2. services.payload_service.generate_payloads_from_domain_waf_info()
       → config.prompts.get_red_team_user_prompt()
       → services.llm_service.chatgpt_completion()
       → OpenAI API (GPT-4)
    3. services.dvwa_service.loginDVWA()
    4. services.dvwa_service.attack_xss_dom() (for each payload)
    5. If bypassed: services.defense_service.generate_defend_rules_and_instructions()
    ↓
Backend Response: {waf_info, payloads, defense_rules}
    ↓
Frontend: Update state → Render results → Auto-switch to Defend tab
```

### CLI Attack Workflow

```
Command: python src/cli/main.py attack -d domain -t type -n num
    ↓
main.py:
    1. detect_waf() → WAFW00F
    2. generate_payloads() → utils.generate_payloads_from_domain_waf_info()
    3. test_payloads() → utils.loginDVWA(), utils.attack_xss_dom()
    4. generate_defense() → utils.generate_defend_rules_and_instructions()
    ↓
Console output + Optional JSON file
```

---

## How to Extend

### Add New Attack Type

**Step 1:** Add attack function to `services/dvwa_service.py`:

```python
def attack_command_injection(payload, session_id):
    url = f"{DVWA_BASE_URL}/vulnerabilities/exec/?ip={payload}"
    response = requests.get(
        url,
        cookies={"PHPSESSID": session_id, "security": DVWA_SECURITY_LEVEL}
    )
    return {
        "status_code": response.status_code,
        "blocked": _check_blocked(response)
    }
```

**Step 2:** Export from `services/__init__.py`:

```python
from .dvwa_service import (
    ...
    attack_command_injection
)
```

**Step 3:** Update `utils.py` for backwards compatibility:

```python
from services import (
    ...
    attack_command_injection
)

__all__ = [..., 'attack_command_injection']
```

**Step 4:** Update `app.py` attack_functions dict:

```python
attack_functions = {
    ...
    "command_injection": utils.attack_command_injection,
}
```

**Step 5:** Update Frontend `App.js` dropdown:

```jsx
<option value="command_injection">Command Injection</option>
```

**Step 6:** Update CLI `main.py`:

```python
attack_funcs = {..., "command_injection": utils.attack_command_injection}
# Add to choices in argparse
```

---

### Customize LLM Prompts

**Edit `config/prompts.py`:**

```python
# Change red team strategy
RED_TEAM_SYSTEM_PROMPT = """
You are a specialized SQL injection expert...
- Focus on blind SQLi techniques
- Use time-based and boolean-based payloads
"""

# Change defense rule format
def get_blue_team_user_prompt(...):
    return f"""Generate rules in AWS WAF JSON format instead of ModSecurity..."""
```

---

### Change DVWA Domain

**Edit `config/settings.py`:**

```python
DVWA_BASE_URL = "http://your-dvwa-domain.com"
DVWA_USERNAME = "your-username"
DVWA_PASSWORD = "your-password"
```

All services will automatically use the new configuration.

---

### Change OpenAI Model

**Edit `config/settings.py`:**

```python
OPENAI_MODEL = "gpt-3.5-turbo"  # Faster and cheaper
# or
OPENAI_MODEL = "gpt-4o"         # More sophisticated payloads
```

---

## Configuration

### Environment Variables (`.env`)

```env
# Required
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxx

# Optional (for frontend)
REACT_APP_API_URL=http://localhost:5000/api
```

**Security:** Add `.env` to `.gitignore` to prevent committing secrets.

---

### Dependencies

**Backend (`requirements.txt`):**
- `flask`, `flask-cors` - Web framework
- `wafw00f` - WAF detection
- `requests` - HTTP client
- `openai` - GPT-4 API (or manual API calls)
- `python-dotenv` - Environment variables

**Frontend (`package.json`):**
- `react`, `react-dom` - UI framework
- `react-scripts` - Build tools
- `tailwindcss` - CSS framework

---

## Development Setup

### Backend

```bash
cd src/gui/backend

# Install dependencies
pip install flask flask-cors wafw00f requests python-dotenv openai

# Create .env file
cat > ../../.env << EOF
OPENAI_API_KEY=sk-proj-xxxxx
EOF

# Start server
python app.py  # Runs on http://localhost:5000
```

### Frontend

```bash
cd src/gui/frontend

# Install dependencies
npm install

# Start dev server
npm start  # Runs on http://localhost:3000
```

### CLI

```bash
# Make executable
chmod +x src/cli/main.py

# Test
python src/cli/main.py detect -d modsec.llmshield.click
```

---

## Testing

### Test Backend Imports

```bash
cd src/gui/backend
python3 -c "from utils import loginDVWA, attack_xss_dom; print('✅ Import successful')"
```

### Test API Endpoint

```bash
curl -X POST http://localhost:5000/api/attack \
  -H "Content-Type: application/json" \
  -d '{"domain": "modsec.llmshield.click", "attack_type": "xss_dom", "num_payloads": 3}'
```

### Test Frontend

Navigate to `http://localhost:3000` and test attack workflow.

### Test CLI

```bash
python src/cli/main.py attack -d modsec.llmshield.click -t xss_dom -n 3 -o test.json
cat test.json | jq '.results[] | select(.bypassed == true)'
```

---

## Troubleshooting

### Error: "Module 'config' not found"

**Cause:** Running from wrong directory.

**Fix:**
```bash
cd /Users/quangnguyen/Desktop/LLM4WAF/src/gui/backend
python app.py
```

### Error: "OPENAI_API_KEY not found"

**Cause:** Missing `.env` file.

**Fix:**
```bash
echo "OPENAI_API_KEY=sk-proj-xxxxx" > .env
```

### Error: "DVWA Connection Failed"

**Cause:** DVWA not running or incorrect domain.

**Fix:**
```bash
# Test DVWA connectivity
curl -I http://modsec.llmshield.click/login.php

# Update domain in config/settings.py
DVWA_BASE_URL = "http://your-domain.com"
```

### Dark Mode Not Persisting

**Solution:** Already fixed in App.js with localStorage persistence.

---

## Code Quality & Best Practices

### Current Benefits

✅ **Modular Architecture:** Clear separation of config, services, and API routes
✅ **Backwards Compatible:** Existing code works without changes via `utils.py`
✅ **Configuration Management:** Centralized in `config/settings.py`
✅ **Prompt Engineering:** Isolated in `config/prompts.py` for easy tuning
✅ **Service Layer:** Testable, reusable business logic
✅ **Documentation:** README files for backend, GUI, CLI, and this file

### Recommended Future Improvements

1. **Unit Tests:** Add pytest tests for each service
2. **Async I/O:** Use asyncio for parallel payload testing
3. **Caching:** Cache WAF detection results
4. **API Authentication:** Add JWT tokens for production
5. **Rate Limiting:** Prevent API abuse
6. **Type Hints:** Add Python type annotations
7. **Error Handling:** More granular exception handling

---

## Documentation Map

| File | Purpose | Audience |
|------|---------|----------|
| **GUI_README.md** | GUI user guide (installation, usage, troubleshooting) | End users |
| **CLI_README.md** | CLI user guide (commands, examples, automation) | DevOps, automation users |
| **INSTRUCTIONS.md** | Project architecture and developer guide | Developers, contributors |
| **src/gui/backend/README.md** | Backend refactored structure | Backend developers |

---

## Version History

### Latest Version (Refactored)

**Features:**
- Modular backend architecture (config/ + services/)
- Automated attack workflow (detect → generate → test → defend)
- Retest functionality for bypassed payloads
- Dark/light theme with localStorage persistence
- CLI support for automation
- JSON export for all data
- Comprehensive documentation

**Pending:**
- Unit tests
- API authentication
- Async payload testing
- WAF detection caching

---

## Support

- **GitHub Issues:** Report bugs and request features
- **Documentation:** See GUI_README.md, CLI_README.md, backend README.md

---

**LLMShield - AI-Powered WAF Testing Platform**
