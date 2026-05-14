from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from datasets import load_dataset
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainerCallback
from peft import LoraConfig, PeftModel, get_peft_model, prepare_model_for_kbit_training
from trl import SFTConfig, SFTTrainer


FINETUNE_ROOT = Path(__file__).resolve().parent
DATA_ROOT = FINETUNE_ROOT / "data" / "processed"
EXPERIMENTS_ROOT = FINETUNE_ROOT / "experiments"


class DetailedLoggingCallback(TrainerCallback):
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def on_log(self, args, state, control, logs=None, **kwargs):
        if not logs:
            return
        step = state.global_step
        epoch = logs.get("epoch")
        loss = logs.get("loss")
        learning_rate = logs.get("learning_rate")

        parts = [f"step={step}"]
        if epoch is not None:
            parts.append(f"epoch={epoch:.2f}")
        if loss is not None:
            parts.append(f"loss={loss:.4f}")
        if learning_rate is not None:
            parts.append(f"lr={learning_rate:.2e}")

        self.logger.info(" | ".join(parts))
        flush_logger(self.logger)

    def on_epoch_end(self, args, state, control, **kwargs):
        self.logger.info("Epoch %.0f completed | global_step=%s", state.epoch or 0, state.global_step)
        flush_logger(self.logger)

    def on_save(self, args, state, control, **kwargs):
        self.logger.info("Checkpoint saved at global_step=%s", state.global_step)
        flush_logger(self.logger)


def flush_logger(logger: logging.Logger) -> None:
    for handler in logger.handlers:
        try:
            handler.flush()
        except Exception:
            pass
    try:
        sys.stdout.flush()
    except Exception:
        pass


def setup_logging(log_prefix: str, log_dir: Path, log_suffix: str = "") -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger_name = f"finetune.{log_prefix}.{int(time.time() * 1000)}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"{log_prefix}_{timestamp}{log_suffix}.log"
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)

    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.info("Logging to %s", log_path)
    return logger


def require_env_token(var: str = "HF_TOKEN") -> str:
    token = os.environ.get(var)
    if token:
        return token

    token_path = Path.home() / ".cache" / "huggingface" / "token"
    if token_path.exists():
        token = token_path.read_text(encoding="utf-8").strip()
        if token:
            os.environ[var] = token
            return token

    raise SystemExit(
        f"Environment variable {var} is not set and no cached Hugging Face token was found at {token_path}."
    )


def parse_visible_devices(gpu_arg: str) -> tuple[bool, int, Any]:
    use_multi_gpu = "," in gpu_arg
    num_gpus = len([item for item in gpu_arg.split(",") if item.strip()]) if gpu_arg else 1

    if not torch.cuda.is_available():
        return False, 0, None

    if use_multi_gpu:
        return True, num_gpus, "auto"

    torch.cuda.set_device(0)
    return False, 1, {"": 0}


def build_bnb_config() -> BitsAndBytesConfig:
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16,
    )


def build_lora_config(target_modules: list[str], lora_r: int = 16, lora_alpha: int = 32, lora_dropout: float = 0.05) -> LoraConfig:
    return LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        target_modules=target_modules,
        lora_dropout=lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
    )


def format_example(tokenizer, example: Dict[str, Any]) -> Dict[str, str]:
    if "text" in example and isinstance(example["text"], str):
        return {"text": example["text"]}

    if "messages" in example:
        text = tokenizer.apply_chat_template(example["messages"], tokenize=False)
        return {"text": text}

    if "instruction" in example and "payload" in example:
        messages = [
            {"role": "user", "content": example["instruction"]},
            {"role": "assistant", "content": example["payload"]},
        ]
        text = tokenizer.apply_chat_template(messages, tokenize=False)
        return {"text": text}

    raise ValueError("Unsupported dataset schema: expected 'messages' or 'instruction'/'payload'.")


def load_model_and_tokenizer_for_sft(
    model_name: str,
    token: str,
    device_map: Any,
    adapter_path: Optional[str],
    target_modules: list[str],
    logger: logging.Logger,
) -> tuple[Any, Any]:
    logger.info("Loading tokenizer: %s", model_name)
    tokenizer = AutoTokenizer.from_pretrained(model_name, token=token, trust_remote_code=True)
    tokenizer.padding_side = "right"
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    logger.info("Loading 4-bit base model: %s", model_name)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        token=token,
        device_map=device_map,
        quantization_config=build_bnb_config(),
        trust_remote_code=True,
        torch_dtype=torch.float16,
    )
    model.gradient_checkpointing_enable()
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(model)

    if adapter_path and Path(adapter_path).exists():
        logger.info("Resuming from adapter: %s", adapter_path)
        model = PeftModel.from_pretrained(model, adapter_path, is_trainable=True)
    else:
        logger.info("Creating fresh LoRA adapter")
        model = get_peft_model(model, build_lora_config(target_modules=target_modules))

    return model, tokenizer


def run_sft_training(config: Dict[str, Any]) -> None:
    model_name = config["model_name"]
    train_path = Path(config["train_path"])
    eval_path = Path(config["eval_path"]) if config.get("eval_path") else None
    output_dir = Path(config["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    logger = setup_logging(config["log_prefix"], output_dir, config.get("log_suffix", ""))
    token = require_env_token(config.get("use_auth_token_env", "HF_TOKEN"))
    use_multi_gpu, num_gpus, device_map = parse_visible_devices(config.get("gpu", "0"))

    logger.info("Train dataset: %s", train_path)
    logger.info("Output dir: %s", output_dir)
    logger.info("GPU setting: %s", config.get("gpu", "0"))

    model, tokenizer = load_model_and_tokenizer_for_sft(
        model_name=model_name,
        token=token,
        device_map=device_map,
        adapter_path=config.get("adapter_path"),
        target_modules=config["target_modules"],
        logger=logger,
    )

    ds = load_dataset("json", data_files={"train": str(train_path)})
    if eval_path and eval_path.exists():
        ds["validation"] = load_dataset("json", data_files={"validation": str(eval_path)})["validation"]

    ds = ds.map(lambda sample: format_example(tokenizer, sample))

    sft_config = SFTConfig(
        output_dir=str(output_dir),
        per_device_train_batch_size=int(config.get("per_device_train_batch_size", 1)),
        per_device_eval_batch_size=int(config.get("per_device_eval_batch_size", 1)),
        gradient_accumulation_steps=int(config.get("gradient_accumulation_steps", 16)),
        num_train_epochs=float(config.get("num_train_epochs", 3)),
        learning_rate=float(config.get("learning_rate", 2e-4)),
        weight_decay=float(config.get("weight_decay", 0.0)),
        warmup_ratio=float(config.get("warmup_ratio", 0.03)),
        lr_scheduler_type=config.get("lr_scheduler_type", "cosine"),
        fp16=bool(config.get("fp16", True)),
        bf16=bool(config.get("bf16", False)),
        logging_steps=int(config.get("logging_steps", 10)),
        save_steps=int(config.get("save_steps", 500)),
        eval_steps=int(config.get("eval_steps", 500)),
        save_total_limit=int(config.get("save_total_limit", 3)),
        optim=config.get("optim", "paged_adamw_8bit"),
        report_to=["tensorboard"],
        logging_dir=str(output_dir / "logs"),
        logging_first_step=True,
        disable_tqdm=False,
        log_level="info",
        dataloader_pin_memory=bool(config.get("dataloader_pin_memory", True)),
        dataloader_num_workers=int(config.get("dataloader_num_workers", 4)),
        dataloader_prefetch_factor=int(config.get("dataloader_prefetch_factor", 2)),
        ddp_find_unused_parameters=False if not use_multi_gpu else None,
        max_length=int(config.get("max_length", 1024)),
        packing=False,
        group_by_length=bool(config.get("group_by_length", True)),
        dataset_text_field="text",
    )

    if config.get("max_steps"):
        sft_config.max_steps = int(config["max_steps"])
    if use_multi_gpu:
        sft_config.ddp_backend = "nccl"
        sft_config.local_rank = int(os.environ.get("LOCAL_RANK", -1))

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        args=sft_config,
        train_dataset=ds["train"],
        eval_dataset=ds.get("validation"),
        callbacks=[DetailedLoggingCallback(logger)],
    )

    effective_batch = (
        int(config.get("per_device_train_batch_size", 1))
        * int(config.get("gradient_accumulation_steps", 16))
        * max(num_gpus, 1)
    )
    logger.info("Dataset size: %s samples", len(ds["train"]))
    logger.info("Effective batch size: %s", effective_batch)

    resume_ckpt = config.get("resume_from_checkpoint")
    if resume_ckpt:
        logger.info("Resuming trainer checkpoint: %s", resume_ckpt)
        trainer.train(resume_from_checkpoint=resume_ckpt)
    else:
        logger.info("Starting SFT training")
        trainer.train()

    trainer.save_model(str(output_dir))
    logger.info("Training complete. Saved to %s", output_dir)
    flush_logger(logger)
