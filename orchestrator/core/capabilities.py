from dataclasses import dataclass
from typing import Dict

@dataclass(frozen=True)
class CapabilityFact:
    capability: str
    target: str
    evidence: str
    confidence: float
    attributes: Dict
    source_tool: str
