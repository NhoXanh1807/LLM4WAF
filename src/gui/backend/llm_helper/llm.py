


import os
from dataclasses import dataclass
from ..config.settings import HF_ACCESS_TOKEN



from typing import List

@dataclass
class PayloadResult:
    payload: str
    technique: str
    attack_type: str
    bypassed: bool
    status_code: int = None

class Gemma2B:
    def __init__(self):
        self.loaded = False
    
    def load_model(self):
        if self.loaded:
            return
        print("Loading Gemma-2-2B model...")
        # Lazy load model dependencies
        import torch
        from transformers import (
            AutoTokenizer,
            AutoModelForCausalLM,
            BitsAndBytesConfig,
        )
        from peft import PeftModel
        
        self.no_grad = torch.no_grad
        # Check for CUDA availability
        if torch.cuda.is_available():
            print("Using CUDA device")
            print([torch.cuda.get_device_name(i) for i in range(torch.cuda.device_count())])
            self.device = torch.device("cuda")
        else:
            print("Using CPU device")
            self.device = torch.device("cpu")
            
        self.base_model = "google/gemma-2-2b-it"
        self.adapter_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'model', f"remote_gemma2_2b_phase3_rl")
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.float16
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            self.base_model, quantization_config=bnb_config, device_map="auto", token=HF_ACCESS_TOKEN
        )
        self.model = PeftModel.from_pretrained(self.model, self.adapter_path).to(self.device)
        self.tokenizer = AutoTokenizer.from_pretrained(self.base_model, token=HF_ACCESS_TOKEN)
        self.loaded = True
        print("Model loaded successfully.")
    
    def _format_prompt(self, prompt: str) -> str:
        return f"<start_of_turn>user\n{prompt}<end_of_turn>\n<start_of_turn>model\n"
    
    def generate_response(self, prompt: str, max_new_tokens: int = 256, temperature: float = 0.7) -> str:
        if not self.loaded:
            self.load_model()
        formatted_prompt = self._format_prompt(prompt)
        inputs = self.tokenizer(formatted_prompt, return_tensors="pt").to(self.model.device)
        input_length = inputs.input_ids.shape[1]
        with self.no_grad():
            outputs = self.model.generate(**inputs, max_new_tokens=max_new_tokens, temperature=temperature, do_sample=True)
        response = self.tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True)
        return response
    
    def clean_payload(self, generated_text: str) -> str:
        payload = generated_text.strip()
        if payload.startswith("```") or payload.startswith("`"):
            lines = payload.split("\n")
            payload = "\n".join([l for l in lines if not l.strip().startswith("`")])
            payload = payload.strip()
        return payload
    
    def build_phase1_prompt(self, waf_name: str, attack_type: str, technique: str) -> str:
        # Simple Phase 1 prompt
        prompt = f"""Generate a {attack_type} payload using {technique} technique to bypass {waf_name} WAF.
Output ONLY the payload string. Do NOT add explanations or code fences."""
        return prompt


    def build_phase3_prompt(self, waf_name: str, attack_type: str, probe_history: List[PayloadResult]) -> str:
        history_str = ""
        for i, h in enumerate(probe_history):
            history_str += f"{i+1}. Payload: `{h.payload}` (Technique: {h.technique}) -> RESULT: {'BYPASSED' if h.bypassed else 'BLOCKED'}\n"

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
