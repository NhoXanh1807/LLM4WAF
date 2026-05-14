"""
DTOs - Data Transfer Objects
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Union

@dataclass
class AttackResult:
    status_code: int|None
    blocked: bool|None

class WAFType(Enum):
    MODSECURITY = "modsec"
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws"
    NAXSI = "naxsi"
    UNKNOWN = "unknown"
    
    @staticmethod
    def from_str(s: str) -> 'WAFType':
        s = s.lower()
        for waf in WAFType:
            if waf.value in s:
                return waf
        return WAFType.UNKNOWN


@dataclass
class ValidationResult:
    is_valid: bool
    waf_type: WAFType = WAFType.UNKNOWN
    error_message: Optional[str] = None
    rule_id: Optional[Union[int, str]] = None
    warnings: Optional[list[str]] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        if self.is_valid:
            return f"Valid ({self.waf_type.value if self.waf_type else 'unknown'})"
        return f"Invalid: {self.error_message}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "waf_type": self.waf_type.value if self.waf_type else None,
            "error_message": self.error_message,
            "rule_id": self.rule_id,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


@dataclass
class ClusterInfo:
    cluster_id: int
    payloads: list[str]
    attack_type: str
    representative_payload: str
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": int(self.cluster_id),
            "payloads": self.payloads,
            "attack_type": self.attack_type,
            "representative_payload": self.representative_payload,
            "size": int(self.size),
        }


@dataclass
class GeneratedRule:
    rule: str
    instructions: str
    waf_type: WAFType
    is_valid: bool = True
    validation_error: Optional[str] = None
    validation_warnings: Optional[list[str]] = None
    source_cluster: Optional[int] = None
    refinement_notes: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "instructions": self.instructions,
            "waf_type": self.waf_type.value,
            "is_valid": self.is_valid,
            "validation_error": self.validation_error,
            "validation_warnings": self.validation_warnings,
            "refinement_notes": self.refinement_notes,
        }


class ExploitStatus(Enum):
    BLOCKED = "blocked"
    PASSED_NO_EFFECT = "passed_no_effect"
    EXPLOITED = "exploited"
    ERROR = "error"


@dataclass
class PayloadResult:
    payload: str
    technique: str
    attack_type: str
    status_code: int | None = None
    is_bypassed: bool | None = None
    is_harmful: bool | None = None


@dataclass
class ExploitResult:
    status: ExploitStatus
    status_code: int
    payload: str
    attack_type: str
    evidence: Optional[str] = None
    evidence_type: Optional[str] = None
    response_snippet: Optional[str] = None
    verification_details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_blocked(self) -> bool:
        return self.status == ExploitStatus.BLOCKED

    @property
    def is_exploited(self) -> bool:
        return self.status == ExploitStatus.EXPLOITED

    @property
    def bypassed_waf(self) -> bool:
        return self.status in (ExploitStatus.PASSED_NO_EFFECT, ExploitStatus.EXPLOITED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "status_code": self.status_code,
            "payload": self.payload,
            "attack_type": self.attack_type,
            "is_blocked": self.is_blocked,
            "is_exploited": self.is_exploited,
            "bypassed_waf": self.bypassed_waf,
            "evidence": self.evidence,
            "evidence_type": self.evidence_type,
            "verification_details": self.verification_details,
        }


@dataclass
class EvaluateSQLResult:
    payload: str
    safe_queries: list[str] = None
    harm_queries: list[str] = None
    error_queries: list[str] = None
    decode_stack: list|None = None
    
@dataclass
class EvaluateXSSResult:
    payload: str
    is_safe: bool = None
    harms: dict|None = None
    decode_stack: list|None = None
    