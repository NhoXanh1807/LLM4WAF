# SQLi protection pack investigation - corrected summary

## Correction

Earlier analysis in this investigation used
`test_gemma2_2b_all_techniques_2026_04_13/attack_gemma2_pretrained/*.json` as
"the April results". That folder is a baseline comparison run against the
**raw, non-fine-tuned** Gemma2 2B model (hence the name) and mostly contains
degenerate, non-functional text (`<?php`, `-- This is just an example...`),
not real adversarial SQLi/XSS payloads. It is not representative of the real
April test.

The real April results (fine-tuned model, same obfuscation technique
vocabulary as the current pipeline) are in
`test_gemma2_2b_all_techniques_2026_04_13/logs/2026-04-13_22-14-32/result_*.txt`
(Phase 1) and `phase3_*.txt` (Phase 3). All numbers below use that dataset.

## Phase 1: April (real) vs August (current)

| WAF | Attack type | April bypass | August bypass |
|---|---|---|---|
| ModSecurity | sql_injection | 18/50 (36%) | 242/250 (97%) |
| ModSecurity | sql_injection_blind | 24/50 (48%) | 242/250 (97%) |
| ModSecurity | xss_dom | 9/50 (18%) | 194/250 (78%) |
| ModSecurity | xss_reflected | 7/50 (14%) | 203/250 (81%) |
| ModSecurity | xss_stored | 38/50 (76%) | 195/250 (78%) |
| Naxsi | sql_injection | 1/50 (2%) | 2/250 (0.8%) |
| Naxsi | sql_injection_blind | 1/50 (2%) | 1/250 (0.4%) |
| Naxsi | xss_dom | 1/50 (2%) | 1/250 (0.4%) |
| Naxsi | xss_reflected | 1/50 (2%) | 1/250 (0.4%) |
| Naxsi | xss_stored | 0/50 (0%) | 1/250 (0.4%) |
| Cloudflare | sql_injection | 14/50 (28%) | 250/250 (100%) |
| Cloudflare | sql_injection_blind | 15/50 (30%) | 250/250 (100%) |
| Cloudflare | xss_dom | 9/50 (18%) | 250/250 (100%) |
| Cloudflare | xss_reflected | 12/50 (24%) | 250/250 (100%) |
| Cloudflare | xss_stored | 41/50 (82%) | 250/250 (100%) |
| AWS | sql_injection | 50/50 (100%) | 250/250 (100%) |
| AWS | sql_injection_blind | 50/50 (100%) | 247/250 (99%) |
| AWS | xss_dom | 12/50 (24%) | 204/250 (82%) |
| AWS | xss_reflected | 11/50 (22%) | 204/250 (82%) |
| AWS | xss_stored | 40/50 (80%) | 213/250 (85%) |

**Real regressions (Phase 1):** ModSecurity and Cloudflare both went from
moderate blocking (14-82% bypass, i.e. they were catching a meaningful
share of attacks) to near-total bypass. Naxsi held steady (~0-2% bypass in
both periods). AWS SQLi was already 100% bypassed in April - the new SQLi
pack has not moved that number.

## Phase 2: replaying the exact April AWS payloads (50 x Phase 1, 50 x Phase 3)
against the current AWS WAF (with the SQLi protection pack)

Script: `replay_april_aws_payloads.py`. Source payloads: the same 50-per-run
jsonl logs above, re-sent against `aws.llmshield.click/portal/search` with
the `X-Lab-Key: llmshield-lab-only` lab header (same endpoint/header as
`_2_attack_phase1.py`). Output: `output_replay_april_aws/`.

| Phase | Attack type | April (real, original attack) | Now (SQLi pack) |
|---|---|---|---|
| Phase 1 | sql_injection | 0/50 bypass (100% blocked) | 49/50 bypass |
| Phase 1 | sql_injection_blind | 0/50 bypass (100% blocked) | 48/50 bypass |
| Phase 3 | sql_injection | 50/50 bypass (0% blocked) | 50/50 bypass |
| Phase 3 | sql_injection_blind | 50/50 bypass (0% blocked) | 50/50 bypass |

The exact same Phase 1 payload set that AWS blocked 100% of the time in
April now bypasses 49/50 and 48/50 - a direct, payload-identical
before/after comparison showing the SQLi pack provides essentially no
protection against this payload set today, even though AWS blocked all of
it 5 months ago. Phase 3 (already fully adaptive/evasive in April) remains
fully bypassed.

## Phase 3: is_harmful breakdown for AWS SQLi (post-pack)

Ran `_4_harmful.py --waf AWS --attack-type sql_injection[_blind]` to flag
which of the 250-per-run payloads are genuinely valid/functional SQL
injection (via `sqlglot`-based parsing), as opposed to malformed/junk text
that happens to bypass for unrelated reasons. Output refreshed in
`output_generate_phase1_harmful/` and `output_generate_phase3_harmful/`
(status_code/is_bypassed there were stale copies from before this
investigation's re-attacks).

| Dataset | Total | Harmful (real SQLi) | Harmful & bypassed | Harmful & blocked |
|---|---|---|---|---|
| Phase 1 sql_injection | 250 | 157 (63%) | 156 (99.4%) | 1 |
| Phase 1 sql_injection_blind | 250 | 161 (64%) | 161 (100%) | 0 |
| Phase 3 sql_injection | 250 | 153 (61%) | 153 (100%) | 0 |
| Phase 3 sql_injection_blind | 250 | 164 (66%) | 162 (98.8%) | 2 |

The handful of payloads the pack does block are mostly **not** real,
parseable SQL injection - of the 3-8 "blocked" payloads per file, only 0-2
were genuinely harmful. The pack's real detection rate against functional
SQL injection is effectively 0-1.2%, worse than the raw bypass numbers
already suggested.
