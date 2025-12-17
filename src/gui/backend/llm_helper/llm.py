
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
from config.settings import HF_ACCESS_TOKEN


def check_gpu():
    if torch.cuda.is_available():
        return [torch.cuda.get_device_name(i) for i in range(torch.cuda.device_count())]
    else:
        return []


from typing import List, Optional



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

class Gemma2B:
    def __init__(self, adapter_path):
        
        # Khởi tạo config
        config = Config(
            model_name="google/gemma-2-2b-it",
            hf_token=HF_ACCESS_TOKEN,
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
        
        # Loading tokenizer
        self.tok = AutoTokenizer.from_pretrained(config.model_name, token=config.hf_token, trust_remote_code=True)
        self.tok.padding_side = config.padding_side
        if self.tok.pad_token is None:
            self.tok.pad_token = self.tok.eos_token
        
        # Bit and Bytes Config for 4-bit quantization
        bit_and_bytes_cfg = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_use_cpu_offload=True,
            bnb_4bit_compute_dtype=torch.float16,
            llm_int8_enable_fp32_cpu_offload=True,
        )
        
        # Loading pretrained model 
        self.model = AutoModelForCausalLM.from_pretrained(
            config.model_name,
            token=config.hf_token,
            device_map={"": 0} if config.is_use_single_gpu else "auto",
            quantization_config=bit_and_bytes_cfg,
            trust_remote_code=True,
            dtype=torch.float16,
        )
        if config.gradient_checkpointing:
            self.model.gradient_checkpointing_enable()
            self.model.config.use_cache = False
        
        if config.adapter_path and os.path.exists(config.adapter_path):
            self.model = PeftModel.from_pretrained(self.model, config.adapter_path, is_trainable=True)
            self.model.config.use_cache = False
        else:
            lora_cfg = LoraConfig(
                r=config.lora_rank,
                lora_alpha=config.lora_alpha,
                target_modules=config.lora_target_modules,
                lora_dropout=float(config.lora_dropout),
                bias="none",
                task_type="CAUSAL_LM",
            )
            self.model = get_peft_model(self.model, lora_cfg)
        
        self.model.eval()
        

    def apply_chat_template(self, prompt: str) -> str:
        if hasattr(self.tok, "chat_template") and self.tok.chat_template:
            messages = [{"role": "user", "content": prompt}]
            return self.tok.apply_chat_template(messages, tokenize=False)
        return prompt

    def generate_once(self, prompt: str, genCfg: GenerationConfig) -> str:
        text = self.apply_chat_template(prompt)
        inputs = self.tok(text, return_tensors="pt").to(self.model.device)
        inputs_length = inputs.input_ids.shape[1]
        with torch.no_grad():
            output_ids = self.model.generate(
                **inputs,
                max_new_tokens=genCfg.max_new_tokens,
                do_sample=genCfg.do_sample,
                temperature=genCfg.temperature,
                top_p=genCfg.top_p,
                top_k=genCfg.top_k,
                repetition_penalty=genCfg.repetition_penalty,
                num_beams=genCfg.num_beams,
                eos_token_id=self.tok.eos_token_id,
                pad_token_id=self.tok.eos_token_id,
            )
        
        generated = self.tok.decode(output_ids[0, inputs_length:], skip_special_tokens=True)
        return generated

model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
gemma_2b_model = Gemma2B(adapter_path=model_path)
