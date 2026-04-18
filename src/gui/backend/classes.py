
from dataclasses import dataclass
@dataclass
class PayloadResult:
    payload: str
    technique: str
    attack_type: str
    bypassed: bool|None = None
    status_code: int|None = None