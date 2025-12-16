

import time
from datasets import load_dataset
import torch
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, PeftModel # Keep PeftModel import for compatibility, though not directly used in this version for initial loading
from trl import SFTTrainer, SFTConfig
from transformers import TrainingArguments, TrainerCallback
import sys
import os
from dataclasses import dataclass


def check_gpu():
    if torch.cuda.is_available():
        print(f"GPU(s) available: {torch.cuda.device_count()}")
        print(f"Current device: {torch.cuda.current_device()}")
        print(f"Device name: {torch.cuda.get_device_name(torch.cuda.current_device())}")
    else:
        print("No GPU found. Training will run on CPU.")
# check_gpu()

class OutputLogger:
    def __init__(self, filename, mode="w", encoding="utf-8"):
        self.file = open(filename, mode, encoding=encoding)
        self.stdout = sys.__stdout__
    def write(self, data):
        self.file.write(data)
        self.stdout.write(data)
    def flush(self):
        self.file.flush()
        self.stdout.flush()
        
session_name = time.strftime("%Y%m%d-%H%M%S")
sys.stdout = OutputLogger(f'output/{session_name}.out')


from typing import List, Optional
@dataclass
class Config:
    # Core model/tokenizer
    model_name: str = ""
    hf_token: str = ""

    # Hardware / execution
    is_use_single_gpu: bool = False
    num_gpus: int = 1
    gradient_checkpointing: bool = True

    # Adapters / LoRA
    adapter_path: Optional[str] = None
    padding_side: str = "right"
    lora_rank: int = 8
    lora_alpha: int = 32
    lora_target_modules: Optional[List[str]] = None
    lora_dropout: float = 0.05

    # Data
    dataset_train_path: str = ""
    dataset_eval_path: str = ""

    # Outputs
    output_dir: Optional[str] = None

    # Trainer config (optional overrides; sensible defaults applied later via .get)
    per_device_train_batch_size: int = 1
    per_device_eval_batch_size: int = 1
    gradient_accumulation_steps: int = 16
    num_train_epochs: float = 2
    learning_rate: float = 2e-4
    weight_decay: float = 0.0
    warmup_ratio: float = 0.03
    lr_scheduler_type: str = "cosine"
    fp16: bool = False
    bf16: bool = False
    logging_steps: int = 10
    save_steps: int = 200
    eval_steps: int = 200
    save_total_limit: int = 2
    optim: str = "paged_adamw_8bit"
    dataloader_pin_memory: bool = True
    dataloader_num_workers: int = 4
    dataloader_prefetch_factor: int = 2
    max_length: int = 2048
    group_by_length: bool = True
    max_steps: int = 0

    logging_callback: Optional[TrainerCallback] = None
    
    def __post_init__(self):
        if self.lora_target_modules is None:
            self.lora_target_modules = [
                "q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"
            ]
    
    def is_valid(self) -> bool:
        return True

# Khởi tạo config
config = Config(
    model_name="google/gemma-2-2b-it",
    hf_token="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",
    dataset_train_path="llm/data/phase1_balanced_10k.jsonl",
    # Tối ưu tận dụng cấu hình máy ảo để tiết kiệm thời gian huấn luyện
    per_device_train_batch_size=1,
    dataloader_num_workers=32,
    gradient_accumulation_steps=16,
    # Lưu 
    max_length=4096,
    save_steps=100,
    eval_steps=100,
    
    adapter_path="",
)
def apply_chat_template(tokenizer: AutoTokenizer, prompt: str) -> str:
    if hasattr(tokenizer, "chat_template") and tokenizer.chat_template and config.use_chat_template:
        messages = [{"role": "user", "content": prompt}]
        return tokenizer.apply_chat_template(messages, tokenize=False)
    return prompt

@dataclass
class GenerationConfig:
    max_new_tokens: int = 512
    do_sample: bool = True
    temperature: float = 0.5
    top_p: float = 0.9
    top_k: int = 50
    repetition_penalty: float = 1.2
    num_beams: int = 1
    use_chat_template: bool = True
def generate_once(model, tokenizer: AutoTokenizer, prompt: str, genCfg: GenerationConfig) -> str:
    text = apply_chat_template(tokenizer, prompt)
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=genCfg.max_new_tokens,
            do_sample=genCfg.do_sample,
            temperature=genCfg.temperature,
            top_p=genCfg.top_p,
            top_k=genCfg.top_k,
            repetition_penalty=genCfg.repetition_penalty,
            num_beams=genCfg.num_beams,
            eos_token_id=tokenizer.eos_token_id,
            pad_token_id=tokenizer.eos_token_id,
        )
    generated = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    return generated

def main() -> None:
    
    # Loading tokenizer
    tok = AutoTokenizer.from_pretrained(config.model_name, token=config.hf_token, trust_remote_code=True)
    tok.padding_side = config.padding_side
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    
    # Bit and Bytes Config for 4-bit quantization
    bit_and_bytes_cfg = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_use_cpu_offload=True,
        bnb_4bit_compute_dtype=torch.float16,
    )
    
    # Loading pretrained model 
    model = AutoModelForCausalLM.from_pretrained(
        config.model_name,
        token=config.hf_token,
        device_map={"": 0} if config.is_use_single_gpu else "auto",
        quantization_config=bit_and_bytes_cfg,
        trust_remote_code=True,
        dtype=torch.float16,
    )
    if config.gradient_checkpointing:
        model.gradient_checkpointing_enable()
        model.config.use_cache = False
    
    if config.adapter_path and os.path.exists(config.adapter_path):
        model = PeftModel.from_pretrained(model, config.adapter_path, is_trainable=True)
        model.config.use_cache = False
    else:
        lora_cfg = LoraConfig(
            r=config.lora_rank,
            lora_alpha=config.lora_alpha,
            target_modules=config.lora_target_modules,
            lora_dropout=float(config.lora_dropout),
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, lora_cfg)
    
    model.eval()

    # Example prompts; replace or extend as needed
    prompts = [
        "Generate a full bypass payload for XSS using obf_double_url_encode+obf_url_encode+obf_case_random_adv_obf_full_bypass.",
        "Craft a time-delay SQL Injection payload for MySQL that leverages the SLEEP function to pause execution for 5 seconds when a specified condition is TRUE, ensuring the delay is triggered only if the database user has administrative privileges. Targeting a MySQL server behind a basic web application firewall. Observed WAF behavior: the following techniques/keywords appear blocked: ['OR', 'UNION', 'AND', 'SLEEP', 'BENCHMARK', 'EXTRACTVALUE', 'UPDATEXML', 'SELECT_USER', 'FROM_USERS', 'WHERE_1=1']. Constraints in your response. Technique: time_based\n\nIMPORTANT: Generate ONLY the payload code. Do not provide explanations, ask questions, or start conversations.",
    ]

    genCfg = GenerationConfig()
    for i, prompt in enumerate(prompts, 1):
        print(f"\n===== Prompt {i} =====")
        print(prompt)
        
        out = generate_once(model, tok, prompt, genCfg)
        print("----- Generation -----")
        print(out)
main()