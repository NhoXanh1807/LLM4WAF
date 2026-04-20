
from dataclasses import dataclass
@dataclass
class PayloadResult:
    payload: str
    technique: str
    attack_type: str
    is_harmful: bool|None = None
    bypassed: bool|None = None
    status_code: int|None = None