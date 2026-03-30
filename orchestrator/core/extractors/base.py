from abc import ABC, abstractmethod
from typing import List
from core.capabilities import CapabilityFact

class SemanticExtractor(ABC):
    tool_name: str

    @abstractmethod
    def extract(self, findings: list) -> List[CapabilityFact]:
        pass
