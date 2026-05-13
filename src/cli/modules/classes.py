from dataclasses import dataclass
from enum import Enum

class OutputType(Enum):
    GENPAYLOAD = "genpayload"
    TEST = "test"
    CLUSTER = "cluster"
    RAG = "rag"
    GENRULE = "genrule"
    VALIDRULE = "validrule"
    INVALIDRULE = "invalidrule"
    FIXEDRULE = "fixedrule"
    FINALRULE = "finalrule"

@dataclass
class File:
    output_type: OutputType
    id: int
    path: str