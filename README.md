# LLM4WAF

LLM4WAF is an experimental framework for two Web Application Firewall workflows:

- `attack`: detect the target WAF, generate WAF-evasive attack payloads, and test those payloads against a real target.
- `defend`: cluster successful bypass payloads, retrieve supporting knowledge through RAG, generate defensive rules, validate rule syntax, repair invalid rules, and refine the final rule set.

The repository centralizes domain logic in `src/core` and reuses that logic from the CLI in `src/cli`, the web application in `src/web`, and evaluation scripts in `src/test`.

## Repository Goals

- Keep business logic in a shared core layer.
- Use LLMs to generate attack payloads that adapt to WAF behavior.
- Use LLMs, RAG, external model APIs, and rule validation to propose defensive rules.
- Support the same pipelines through multiple interfaces: CLI, Web API, frontend UI, and testing scripts.

## Project Structure

```text
LLM4WAF/
├─ requirements.txt
├─ src/
│  ├─ cli/
│  │  ├─ main.py
│  │  ├─ outputs_index.json
│  │  ├─ outputs/
│  │  └─ modules/
│  ├─ core/
│  │  ├─ attack_pipeline.py
│  │  ├─ defend_pipeline.py
│  │  ├─ config/
│  │  ├─ external_services/
│  │  ├─ models/
│  │  ├─ services/
│  │  └─ utils/
│  ├─ web/
│  │  ├─ backend/
│  │  └─ frontend/
│  └─ test/
└─ venv/
```

## Core Components

### 1. `src/core`

`src/core` is the center of the system and contains most of the domain logic.

After the refactor, the package is organized around two top-level pipelines:

- `attack_pipeline.py`: the offensive workflow.
  - `_1_detect_waf(domain)`: identifies the target WAF using `wafw00f`.
  - `_2_generate_payload(...)`: generates Phase 1 payloads (random payloads) or Phase 3 payloads (adaptive payloads) depending on whether probe history is available.
  - `_3_test_attack(...)`: tests generated payloads against DVWA or a real WAF-protected target and evaluates harmfulness.
- `defend_pipeline.py`: the defensive workflow.
  - `_1_clustering(...)`: clusters bypass payloads.
  - `_2_rag_retrieve(...)`: retrieves supporting knowledge from LLMShield or another RAG source.
  - `_3_generate_rules(...)`: generates defensive rules with an LLM.
  - `_4_validate_rules_syntax(...)`: validates rule syntax for a specific WAF.
  - `_5_retry_invalid_rules(...)`: retries or repairs invalid rules.
  - `_6_refine_rules(...)`: refines the final rule set and can optionally merge with existing rules.

These two modules define the highest-level business workflows. The other directories under `src/core` mainly support those pipelines.

#### `src/core/services`

- `generator.py`: payload generation logic for the attack workflow.
  - Phase 1: generates payloads using random obfuscation techniques.
  - Phase 3: generates adaptive payloads from probe history.
- `clustering.py`: clusters payloads using TF-IDF, dimensionality reduction, and HDBSCAN or HAC.
- `sql_harmfulness_validator.py`: evaluates the harmfulness of SQL payloads.
- `rule_syntax_validator/`: validates rule syntax for supported WAFs such as ModSecurity, AWS WAF, Cloudflare, and Naxsi.

#### `src/core/utils`

- `utils.py`: shared utility functions used by the core layer, currently focused on normalization and multi-layer payload decoding and de-obfuscation.

#### `src/core/external_services`

This package integrates with external systems:

- `llmshield.py`: calls LLMShield to build prompts, generate payloads, and perform RAG retrieval.
- `llm_api.py`: calls external LLM providers such as OpenAI and Claude to generate, repair, and refine rules.
- `xss_harmfulness_validator.py`: calls `llm4waf_services` to evaluate the harmfulness of XSS payloads.
- `dvwa.py`: logs in to DVWA and submits payloads to the relevant test endpoints.

#### `src/core/models`

- `dtos.py`: shared DTOs and data structures.

Examples include:

- `PayloadResult`
- `AttackResult`
- `ValidationResult`
- `WAFType`

#### `src/core/config`

- `prompts.py`: prompt templates and prompt builders used for rule generation, retry, refinement, and other defensive stages.
- `settings.py`: loads environment configuration from `src/core/.env`.

Important environment variables include:

- `OPENAI_API_KEY`
- `CLAUDE_API_KEY`
- `LLMSHIELD_ENDPOINT`
- `XSS_HARMNESS_VALIDATOR_ENDPOINT`

### 2. `src/cli`

The CLI provides an interactive command-line interface for running the system.

- `main.py`: CLI entry point.
- `modules/command_builder.py`: defines the command tree and the mechanism for requesting missing parameters interactively.
- `modules/handlers.py`: maps CLI commands to the corresponding pipelines in `core`.
- `modules/file_manager.py`: stores per-step results in `outputs/` and manages the output index in `outputs_index.json`.

The CLI does not implement its own business logic. It delegates to `core` and stores each step result as JSON so that later stages can reuse earlier outputs.

### 3. `src/web`

#### `src/web/backend`

The backend is a Flask application that exposes HTTP APIs for both attack and defend workflows.

Main endpoint groups:

- `/api/attack/1-detect-waf`
- `/api/attack/2-generate-payload`
- `/api/attack/3-test`
- `/api/defend/1-clustering`
- `/api/defend/2-rag-retrieve`
- `/api/defend/3-generate-rules`
- `/api/defend/4-validate-rules`
- `/api/defend/5-retry-invalid-rules`
- `/api/defend/6-refine-rules`

Like the CLI, the backend is a thin wrapper around `core.attack_pipeline` and `core.defend_pipeline`.

#### `src/web/frontend`

The frontend is a React application that interacts with the backend over HTTP. It is intended for demos or interactive operation when a graphical interface is preferable to the CLI.

### 4. `src/test`

This directory contains scenario-specific test and evaluation scripts. In practice, its subdirectories reuse logic from `core` to validate system behavior for different experiments. It should not be treated as a unified test framework; it is better understood as a collection of scripts and artifacts for system-level evaluation.

## End-to-End Workflows

### Attack Flow

1. Detect the target WAF from the target domain.
2. Generate WAF-evasive payloads.
3. Test the payloads against the real target, determine whether they bypass the WAF, and evaluate whether they are harmful.

### Defend Flow

Input: payloads that successfully bypassed the WAF and were classified as harmful during the attack flow.

1. Cluster payloads to identify similar attack behavior.
2. Retrieve knowledge relevant to the WAF and attack type through RAG.
3. Generate candidate defensive rules with an LLM.
4. Validate rule syntax.
5. Retry or repair invalid rules.
6. Refine the final rule set, optionally with existing rules as additional context.

## External Service Assumptions

`src/core` depends directly on several external services. These services should be treated as prerequisites for successful operation:

- `llmshield` must be available and stable for payload generation and RAG retrieval.
- `llm_api` must be able to access external providers such as OpenAI and Claude for rule generation, repair, and refinement.
- `xss_harmness_validator` must be available for XSS harmfulness evaluation.
- `dvwa` and the target WAF environment must be available for live payload testing.

In short, the external services must be healthy for `src/core` to function correctly, and therefore for the CLI, web layer, and test scripts that depend on it to work reliably.

## Environment Requirements

### Python

Install the Python dependencies listed in `requirements.txt`:

```powershell
cd LLM4WAF
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
```

### Node.js for the Frontend

The frontend is a React application. Install its dependencies with:

```powershell
cd src/web/frontend
npm install
```

## Environment Configuration

Create `src/core/.env` with the minimum required variables based on `src/core/.env.example`.

Also create `.env` under `src/web/frontend` based on `src/web/frontend/.env.example`.

## Usage

### 1. Run the CLI

From the repository root:

```powershell
cd src/cli
python main.py
```

The CLI runs interactively. If required parameters are missing, it will prompt for them in the terminal.

#### Main Commands

```text
attack detect <domain>
attack generate <waf_name> <attack_type> <num> [tested_file]
attack test <domain> <generate_file>
attack auto <domain> <attack_type> <num> <num_adaptive>

defend cluster <bypassed_file>
defend rag <waf_name> <attack_type> <bypassed_file>
defend genrule <waf_name> <cluster_file> [rag_file]
defend validate <genrule_file>
defend retry <waf_name> <invalidrule_file>
defend refine <waf_name> <validrule_file> [fixedrule_file] [existing_rule_file_path]
defend auto <waf_name> <attack_type> <bypassed_file> [existing_rule_file_path]

files all
files view <file_id>
files remove <file_id>
exit
```

Outputs from each step are stored in:

- `src/cli/outputs/`
- `src/cli/outputs_index.json`

This makes it possible to feed the output of one step into the next step, or to automate the entire workflow through the `auto` commands.

#### 1.1 Run the Full Attack Pipeline Automatically

Provide the target domain, the attack type, the initial number of random payloads, and the number of adaptive payloads to generate in the second round:

```text
attack auto example.com sql_injection 5 3
```

The system will automatically:

1. detect the WAF from the target domain,
2. generate random payloads,
3. test the random payloads,
4. generate adaptive payloads from the test result if `num_adaptive > 0`,
5. test the adaptive payloads,
6. save each output independently and also save a merged test output containing both random and adaptive results.

#### 1.2 Run the Full Defend Pipeline Automatically

Once a test output file is available, provide `waf_name`, `attack_type`, and `bypassed_file`. You can also pass `existing_rule_file_path` if refinement should consider an existing ruleset:

```text
defend auto ModSecurity sql_injection test0
```

Example with existing rules:

```text
defend auto ModSecurity sql_injection test0 C:\rules\modsecurity.conf
```

The system will use the specified `bypassed_file` as input for clustering, RAG retrieval, rule generation, validation, retry when needed, refinement, and output persistence for every stage.

#### 1.3 Run Individual Steps Manually

You can also run each stage independently:

```text
attack detect example.com
attack generate ModSecurity sql_injection 5
attack test http://modsec.llmshield.click genpayload0

defend cluster test0
defend rag ModSecurity sql_injection test0
defend genrule ModSecurity cluster0 rag0
defend validate genrule0
defend retry ModSecurity invalidrule0
defend refine ModSecurity validrule0 fixedrule0
defend refine ModSecurity validrule0 fixedrule0 C:\rules\modsecurity.conf
```

### 2. Run the Web Application

#### 2.1 Run the Backend

```powershell
cd src/web/backend
python app.py
```

The backend runs by default at:

```text
http://0.0.0.0:5000
```

The API routes are exposed under the `/api` prefix.

#### 2.2 Run the Frontend

```powershell
cd src/web/frontend
npm install
npm start
```

The frontend calls the backend through `REACT_APP_API_URL`.

The web UI is served at `http://127.0.0.1:3000` and provides the same end-to-end attack and defend capabilities as the CLI in a more accessible interactive interface.
