
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
class PayloadResult:
    payload: str
    technique: str
    passed: bool

class Gemma2B:
    def __init__(self, phase=3):

        if phase not in [1,3]:
            raise ValueError("Phase must be 1 or 3")

        self.base_model = "google/gemma-2-2b-it"
        self.adapter_path = os.join(os.abspath(os.path.dirname(__file__)), f"remote_gemma2_2b_phase3_rl")
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.float16
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            self.base_model, quantization_config=bnb_config, device_map="auto", token=HF_ACCESS_TOKEN
        )
        self.model = PeftModel.from_pretrained(self.model, self.adapter_path)
        self.tokenizer = AutoTokenizer.from_pretrained(self.base_model, token=HF_ACCESS_TOKEN)
        
    def _format_prompt(self, prompt: str) -> str:
        return f"<start_of_turn>user\n{prompt}<end_of_turn>\n<start_of_turn>model\n"
    
    def generate_response(self, prompt: str, max_new_tokens: int = 256, temperature: float = 0.7) -> str:
        formatted_prompt = self._format_prompt(prompt)
        inputs = self.tokenizer(formatted_prompt, return_tensors="pt").to(self.model.device)
        input_length = inputs.input_ids.shape[1]
        with torch.no_grad():
            outputs = self.model.generate(**inputs, max_new_tokens=max_new_tokens, temperature=temperature, do_sample=True)
        response = self.tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True)
        return response
    
    def build_phase1_prompt(self, waf_name: str, attack_type: str, technique: str) -> str:
        # Simple Phase 1 prompt
        prompt = f"""Generate a {attack_type} payload using {technique} technique to bypass {waf_name} WAF.
Output ONLY the payload string. Do NOT add explanations or code fences."""
        return prompt


    def build_phase3_prompt(self, waf_name: str, attack_type: str, probe_history: List[PayloadResult]) -> str:
        history_str = ""
        for i, h in enumerate(probe_history):
            history_str += f"{i+1}. Payload: `{h.payload}` (Technique: {h.technique}) -> RESULT: {h.passed}\n"

        prompt = f"""You are an offensive security assistant specialized in generating WAF-evasion payloads.

Context:
- Target WAF: {waf_name}.
- Attack type: {attack_type}.
- Injection point: query parameter.

[Probing History - Previous Attempts]
{history_str}

Your Task:
Analyze the Probing History above.
- If a specific technique or pattern PASSED, analyze why and generate a similar but new payload.
- If all attempts were BLOCKED, try a completely DIFFERENT technique from the ones listed.
- Generate a NEW payload targeting: Double URL Encode (Adaptive).

IMPORTANT:
- Output ONLY the final payload string.
- Do NOT add explanations.
- Do NOT wrap in code fences."""
        return prompt


gemma_2b_model = Gemma2B()
