
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
        exit()
check_gpu()

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
)

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

    # Load datasets
    ds = load_dataset("json", data_files={"train": config.dataset_train_path})
    if config.dataset_eval_path and os.path.exists(config.dataset_eval_path):
        ds["validation"] = load_dataset("json", data_files={"validation": config.dataset_eval_path})["validation"]


    # Pre-process dataset to create a single 'text' column
    def format_example(example):
        if "messages" in example:
            # Handle chat format directly
            text = tok.apply_chat_template(example["messages"], tokenize=False)
        elif hasattr(tok, "chat_template") and tok.chat_template and "instruction" in example:
            messages = [
                {"role": "user", "content": example["instruction"]},
                {"role": "assistant", "content": example["payload"]},
            ]
            # Apply chat template but don't tokenize yet
            text = tok.apply_chat_template(messages, tokenize=False)
        else:
            # Fallback for simple instruction/payload without chat template
            text = f"User: {example.get('instruction', '')}\nAssistant: {example.get('payload', '')}{tok.eos_token}"
        return {"text": text}


    # We map the formatting function to the dataset
    # Support both 'messages' and 'instruction'/'payload' formats
    if "messages" in ds["train"].column_names or ("instruction" in ds["train"].column_names and "payload" in ds["train"].column_names):
        ds = ds.map(format_example)
    
    # SFTConfig setup
    sft_config = SFTConfig(
        output_dir=config.output_dir,
        per_device_train_batch_size=int(config.per_device_train_batch_size),
        per_device_eval_batch_size=int(config.per_device_eval_batch_size),
        gradient_accumulation_steps=int(config.gradient_accumulation_steps),
        num_train_epochs=float(config.num_train_epochs),
        learning_rate=float(config.learning_rate),
        weight_decay=float(config.weight_decay),
        warmup_ratio=float(config.warmup_ratio),
        lr_scheduler_type=config.lr_scheduler_type,
        fp16=bool(config.fp16),
        bf16=bool(config.bf16),
        logging_steps=int(config.logging_steps),
        save_steps=int(config.save_steps),
        eval_steps=int(config.eval_steps),
        save_total_limit=int(config.save_total_limit),
        optim=config.optim,
        report_to=["tensorboard"],
        logging_dir=f"{config.output_dir}/logs",
        logging_first_step=True,
        disable_tqdm=False,
        log_level="info",
        dataloader_pin_memory=bool(config.dataloader_pin_memory),
        dataloader_num_workers=int(config.dataloader_num_workers),
        dataloader_prefetch_factor=int(config.dataloader_prefetch_factor),
        ddp_find_unused_parameters=(not config.is_use_single_gpu),
        max_length=int(config.max_length),
        packing=False,
        group_by_length=bool(config.group_by_length),
        dataset_text_field="text",
    )
    
    # Multi-GPU specific settings
    if config.is_use_single_gpu == False:
        sft_config.ddp_backend = "nccl"  # Best for multi-GPU
        sft_config.local_rank = -1  # For torchrun

    if int(getattr(config, "max_steps", 0)) > 0:
        sft_config.max_steps = int(config.max_steps)

    print(f"[DEBUG] fp16: {sft_config.fp16}, bf16: {sft_config.bf16}")
    trainer = SFTTrainer(
        model=model,
        processing_class=tok,
        args=sft_config,
        train_dataset=ds["train"],
        eval_dataset=ds.get("validation"),
    )
    if config.logging_callback:
        trainer.add_callback(config.logging_callback)

    # Tính toán chỉ để hiểu, không sử dụng đến giá trị này
    # num_gpus = max(1, int(config.num_gpus))
    # effective_batch = sft_config.per_device_train_batch_size * sft_config.gradient_accumulation_steps * num_gpus
    
    trainer.train()
    
    trainer.save_model(config.output_dir)

main()