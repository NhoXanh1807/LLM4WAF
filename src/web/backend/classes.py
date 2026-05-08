
from dataclasses import dataclass
@dataclass
class PayloadResult:
    payload: str
    technique: str
    attack_type: str
    status_code: int|None = None
    is_bypassed: bool|None = None
    is_harmful: bool|None = None