import json
import logging
import os
import random
import re
from pathlib import Path

from config_utils import load_phase_config, resolve_path, resolve_paths


CONFIG = load_phase_config("phase3.yaml")
os.environ["CUDA_VISIBLE_DEVICES"] = str(CONFIG.get("gpu", "0"))

import httpx
import torch
from torch.optim import AdamW
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel, prepare_model_for_kbit_training

from common import flush_logger, require_env_token, setup_logging


ATTACK_TECHNIQUES = {
    "SQLI": ["Double URL Encode", "Comment Obfuscation", "Boolean OR", "UNION SELECT"],
    "XSS": ["Event Handler", "Script Tag", "IMG onerror", "SVG onload"],
}


def parse_probe_dataset_paths(raw_value: list[str]) -> list[Path]:
    return [Path(item) for item in raw_value]


def normalize_result(value: str | None) -> str | None:
    if not value:
        return None
    lowered = value.strip().lower()
    if lowered in {"passed", "pass", "success", "reflected_no_exec", "sql_error_bypass"}:
        return "PASSED"
    if lowered in {"blocked", "failed_waf_filter", "failed", "error", "unknown"}:
        return "BLOCKED"
    return None


def extract_payload(record: dict) -> str | None:
    payload = record.get("payload")
    if isinstance(payload, str) and payload.strip():
        return payload.strip()

    messages = record.get("messages") or []
    if len(messages) > 1 and isinstance(messages[1], dict):
        candidate = messages[1].get("content")
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return None


def load_probe_pools(paths: list[Path], logger: logging.Logger) -> dict[str, dict[str, list[dict[str, str]]]]:
    pools = {
        "SQLI": {"PASSED": [], "BLOCKED": []},
        "XSS": {"PASSED": [], "BLOCKED": []},
    }

    for path in paths:
        if not path.exists():
            logger.warning("Skipping missing probe dataset: %s", path)
            continue
        logger.info("Loading probe dataset: %s", path)
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                attack_type = str(record.get("attack_type", "")).upper()
                if attack_type not in pools:
                    continue
                payload = extract_payload(record)
                result = normalize_result(record.get("result") or record.get("status"))
                if not payload or not result:
                    continue
                pools[attack_type][result].append(
                    {
                        "payload": payload,
                        "technique": str(record.get("technique", "Unknown")),
                        "source": path.name,
                    }
                )

    for attack_type, result_map in pools.items():
        logger.info(
            "Probe pool %s: %s passed | %s blocked",
            attack_type,
            len(result_map["PASSED"]),
            len(result_map["BLOCKED"]),
        )
    return pools


class AdaptiveReinforceEnv:
    def __init__(
        self,
        waf_base_url: str,
        username: str,
        password: str,
        probe_pools: dict[str, dict[str, list[dict[str, str]]]],
        num_probes: int,
        probe_pass_ratio: float,
        max_steps: int,
        logger: logging.Logger,
    ) -> None:
        self.base_url = waf_base_url.rstrip("/")
        self.username = username
        self.password = password
        self.probe_pools = probe_pools
        self.num_probes = num_probes
        self.probe_pass_ratio = probe_pass_ratio
        self.max_steps = max_steps
        self.logger = logger
        self.client = httpx.Client(timeout=10.0, follow_redirects=True)
        self.current_step = 0
        self.attack_type = "SQLI"
        self.target_technique = "Double URL Encode"
        self.probe_history: list[dict[str, str]] = []
        self.generated_history: list[dict[str, str | bool]] = []

    def _login(self) -> bool:
        login_url = f"{self.base_url}/login.php"
        try:
            response = self.client.get(login_url)
            token_match = re.search(r"user_token['\"]?\s*value=['\"]([a-f0-9]{32})", response.text, re.I)
            data = {"username": self.username, "password": self.password, "Login": "Login"}
            if token_match:
                data["user_token"] = token_match.group(1)
            response = self.client.post(login_url, data=data)
            return "login.php" not in str(response.url).lower()
        except Exception as exc:
            self.logger.error("DVWA login failed: %s", exc)
            return False

    def reset(self, attack_type: str, target_technique: str) -> dict:
        self.attack_type = attack_type
        self.target_technique = target_technique
        self.current_step = 0
        self.generated_history = []
        self.probe_history = self._probe_waf()
        return self._get_state()

    def _sample_probe_examples(self, label: str, count: int) -> list[dict[str, str]]:
        pool = self.probe_pools[self.attack_type][label]
        if not pool:
            return []
        if len(pool) <= count:
            return list(pool)
        return random.sample(pool, count)

    def _probe_waf(self) -> list[dict[str, str]]:
        num_passed = int(self.num_probes * self.probe_pass_ratio)
        num_blocked = max(0, self.num_probes - num_passed)
        probes = self._sample_probe_examples("PASSED", num_passed) + self._sample_probe_examples("BLOCKED", num_blocked)
        random.shuffle(probes)
        results = []
        for probe in probes:
            status = self._execute_attack(probe["payload"])
            results.append(
                {
                    "payload": probe["payload"],
                    "technique": probe["technique"],
                    "result": status,
                    "source": probe["source"],
                }
            )
        return results

    def _get_state(self) -> dict:
        blocked = [item for item in self.probe_history if item["result"] == "BLOCKED"][:3]
        passed = [item for item in self.probe_history if item["result"] == "PASSED"][:2]
        return {
            "waf_type": "ModSecurity + OWASP CRS",
            "attack_type": self.attack_type,
            "injection_point": "query parameter",
            "blocked_examples": blocked,
            "passed_examples": passed,
            "generated_history": list(self.generated_history),
            "target_technique": self.target_technique,
        }

    def _execute_attack(self, payload: str) -> str:
        if self.attack_type == "SQLI":
            target_url = f"{self.base_url}/vulnerabilities/sqli/"
            params = {"id": payload, "Submit": "Submit"}
        else:
            target_url = f"{self.base_url}/vulnerabilities/xss_r/"
            params = {"name": payload, "Submit": "Submit"}

        try:
            response = self.client.get(target_url, params=params)
            body = response.text.lower()
            if response.status_code == 403 or "403 forbidden" in body or "not acceptable" in body:
                return "BLOCKED"
            if self.attack_type == "SQLI":
                if "first name" in body and "surname" in body:
                    return "PASSED"
                if "error" in body:
                    return "PASSED"
                return "FAILED"
            if payload.lower() in body:
                return "PASSED"
            return "FAILED"
        except Exception as exc:
            self.logger.error("Request error while testing payload: %s", exc)
            return "ERROR"

    def step(self, payload: str) -> tuple[dict, float, bool, dict]:
        self.current_step += 1
        if any(item["payload"] == payload for item in self.generated_history):
            reward = -0.5
            done = self.current_step >= self.max_steps
            self.generated_history.append({"payload": payload, "blocked": False, "result": "REPEATED"})
            return self._get_state(), reward, done, {"status": "REPEATED"}

        status = self._execute_attack(payload)
        reward = -0.01
        done = False
        if status == "PASSED":
            reward += 1.0
            done = True
        elif status == "BLOCKED":
            reward += -1.0
        elif status == "FAILED":
            reward += -0.1
        else:
            reward += -1.0

        self.generated_history.append({"payload": payload, "blocked": status == "BLOCKED", "result": status})
        if self.current_step >= self.max_steps:
            done = True
        return self._get_state(), reward, done, {"status": status}

    def close(self) -> None:
        self.client.close()


def build_phase3_prompt(state: dict) -> str:
    attack_type = "SQL injection" if state["attack_type"] == "SQLI" else "XSS"
    blocked = state.get("blocked_examples", [])
    passed = state.get("passed_examples", [])
    generated_history = state.get("generated_history", [])

    blocked_str = "\n".join(f"- {item['payload']} | technique={item['technique']}" for item in blocked) or "- none"
    passed_str = "\n".join(f"- {item['payload']} | technique={item['technique']}" for item in passed) or "- none"
    generated_str = "\n".join(
        f"- {item['payload']} | result={item['result']}" for item in generated_history
    ) or "- none"

    return f"""You are an offensive security assistant specialized in generating WAF-evasion payloads.

Context:
- Target WAF: {state['waf_type']}.
- Attack type: {attack_type}.
- Injection point: {state['injection_point']}.
- Target technique: {state['target_technique']}.

Probe observations from previously labeled payloads:
PASSED:
{passed_str}

BLOCKED:
{blocked_str}

Payloads already generated in this RL episode:
{generated_str}

Task:
Generate one NEW payload that preserves the core attack behavior, learns from the passed examples if any, avoids repeating blocked structures, and stays compact.

IMPORTANT:
- Output ONLY the final payload string.
- Do NOT add explanations or code fences.
"""


def format_chat_prompt(tokenizer, prompt: str) -> str:
    if getattr(tokenizer, "chat_template", None):
        return tokenizer.apply_chat_template([{"role": "user", "content": prompt}], tokenize=False, add_generation_prompt=True)
    return f"<start_of_turn>user\n{prompt}<end_of_turn>\n<start_of_turn>model\n"


def load_model_for_rl(base_model: str, adapter_path: str, token: str, logger: logging.Logger):
    logger.info("Loading RL base model %s with adapter %s", base_model, adapter_path)
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        quantization_config=BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.float16,
        ),
        device_map="auto",
        torch_dtype=torch.float16,
        token=token,
    )
    model = prepare_model_for_kbit_training(model)
    model = PeftModel.from_pretrained(model, adapter_path, is_trainable=True)
    model.gradient_checkpointing_enable()
    model.enable_input_require_grads()

    tokenizer = AutoTokenizer.from_pretrained(base_model, token=token)
    tokenizer.padding_side = "left"
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return model, tokenizer


def generate_payload(model, tokenizer, prompt_text: str, max_context_length: int, max_new_tokens: int) -> str:
    formatted = format_chat_prompt(tokenizer, prompt_text)
    inputs = tokenizer(
        formatted,
        return_tensors="pt",
        truncation=True,
        max_length=max_context_length - max_new_tokens,
    ).to(model.device)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=True,
            temperature=0.8,
            top_p=0.9,
            pad_token_id=tokenizer.pad_token_id,
            use_cache=False,
        )
    response_ids = outputs[0][inputs.input_ids.shape[1]:]
    response = tokenizer.decode(response_ids, skip_special_tokens=True).strip()
    if "<start_of_turn>" in response:
        response = response.split("<start_of_turn>")[0].strip()
    return response.splitlines()[0].strip() if response else ""


def compute_log_prob(model, tokenizer, prompt_text: str, response_text: str, max_context_length: int) -> torch.Tensor:
    formatted = format_chat_prompt(tokenizer, prompt_text)
    full_text = formatted + response_text
    full_ids = tokenizer(full_text, return_tensors="pt", truncation=True, max_length=max_context_length).input_ids.to(model.device)
    prompt_ids = tokenizer(formatted, return_tensors="pt", truncation=True, max_length=max_context_length).input_ids.to(model.device)
    prompt_len = prompt_ids.shape[1]

    autocast_enabled = torch.cuda.is_available()
    with torch.amp.autocast(device_type="cuda", dtype=torch.float16, enabled=autocast_enabled):
        outputs = model(full_ids, use_cache=False)
        logits = outputs.logits

    shift_logits = logits[..., :-1, :].contiguous()
    shift_labels = full_ids[..., 1:].contiguous()
    losses = torch.nn.CrossEntropyLoss(reduction="none")(
        shift_logits.view(-1, shift_logits.size(-1)),
        shift_labels.view(-1),
    ).view(shift_labels.size())

    response_losses = losses[..., max(prompt_len - 1, 0):]
    sequence_log_prob = (-response_losses).mean()

    del outputs, logits, shift_logits, shift_labels, losses, response_losses, full_ids, prompt_ids
    return sequence_log_prob


def main() -> None:
    output_dir = Path(resolve_path(CONFIG["output_dir"]))
    output_dir.mkdir(parents=True, exist_ok=True)
    logger = setup_logging(str(CONFIG.get("log_prefix", "train_phase3")), output_dir, str(CONFIG.get("log_suffix", "")))
    token = require_env_token(str(CONFIG.get("use_auth_token_env", "HF_TOKEN")))
    probe_pools = load_probe_pools(parse_probe_dataset_paths(resolve_paths(CONFIG.get("probe_datasets", []))), logger)

    env = AdaptiveReinforceEnv(
        waf_base_url=str(CONFIG["waf_base_url"]),
        username=str(CONFIG["dvwa_username"]),
        password=str(CONFIG["dvwa_password"]),
        probe_pools=probe_pools,
        num_probes=int(CONFIG.get("num_probes", 10)),
        probe_pass_ratio=float(CONFIG.get("probe_pass_ratio", 0.5)),
        max_steps=int(CONFIG.get("max_steps", 3)),
        logger=logger,
    )
    if not env._login():
        raise SystemExit(
            "Could not log in to the local WAF/DVWA target. Start local_waf/docker-compose.yml and run local_waf/setup_dvwa_db.py first."
        )

    model, tokenizer = load_model_for_rl(str(CONFIG["base_model"]), resolve_path(CONFIG["adapter_path"]), token, logger)
    optimizer = AdamW(model.parameters(), lr=float(CONFIG.get("lr", 1.0e-6)))

    baseline_reward = 0.0
    alpha = 0.1
    logger.info(
        "Starting Phase 3 RL: epochs=%s batch_size=%s max_steps=%s",
        int(CONFIG.get("epochs", 150)),
        int(CONFIG.get("batch_size", 1)),
        int(CONFIG.get("max_steps", 3)),
    )

    for epoch in range(int(CONFIG.get("epochs", 150))):
        logger.info("=== Epoch %s/%s ===", epoch + 1, int(CONFIG.get("epochs", 150)))
        batch_rewards = []
        batch_loss = 0.0

        for _ in range(int(CONFIG.get("batch_size", 1))):
            attack_type = "SQLI" if random.random() < 0.7 else "XSS"
            technique = random.choice(ATTACK_TECHNIQUES[attack_type])
            state = env.reset(attack_type=attack_type, target_technique=technique)

            done = False
            episode_reward = 0.0
            episode_samples: list[tuple[str, str]] = []

            while not done:
                prompt_text = build_phase3_prompt(state)
                payload = generate_payload(
                    model,
                    tokenizer,
                    prompt_text,
                    int(CONFIG.get("max_context_length", 1024)),
                    int(CONFIG.get("max_new_tokens", 256)),
                )
                if not payload:
                    payload = ""
                episode_samples.append((prompt_text, payload))
                state, reward, done, info = env.step(payload)
                episode_reward += reward
                logger.info("Episode step=%s reward=%.3f status=%s payload=%s", env.current_step, reward, info["status"], payload[:120])

            advantage = max(-10.0, min(10.0, episode_reward - baseline_reward))

            for prompt_text, payload in episode_samples:
                optimizer.zero_grad()
                log_prob = compute_log_prob(model, tokenizer, prompt_text, payload, int(CONFIG.get("max_context_length", 1024)))
                loss = -(log_prob * advantage) / max(int(CONFIG.get("batch_size", 1)), 1)
                batch_loss += float(loss.item())
                loss.backward()
                optimizer.step()
                del loss, log_prob
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()

            batch_rewards.append(episode_reward)

        avg_reward = sum(batch_rewards) / max(len(batch_rewards), 1)
        baseline_reward = (1 - alpha) * baseline_reward + alpha * avg_reward
        logger.info("Epoch %s summary | avg_reward=%.4f baseline=%.4f loss=%.4f", epoch + 1, avg_reward, baseline_reward, batch_loss)
        flush_logger(logger)

        if (epoch + 1) % int(CONFIG.get("save_every", 5)) == 0:
            checkpoint_dir = output_dir / f"checkpoint-{epoch + 1}"
            model.save_pretrained(checkpoint_dir)
            logger.info("Saved checkpoint to %s", checkpoint_dir)

    model.save_pretrained(output_dir)
    logger.info("Training complete. Model saved to %s", output_dir)
    env.close()
    flush_logger(logger)


if __name__ == "__main__":
    main()
