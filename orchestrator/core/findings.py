from dataclasses import dataclass, field
from typing import Dict, Any, Optional

@dataclass
class StandardFinding:
    """
    A universal, standardized data structure for any piece of information 
    discovered by a scanning tool. This allows the engine to understand 
    and react to findings in a tool-agnostic way.
    
    Layer separation:
    - facts: Atomic observations (service=ssh, port=22, os=linux)
    - finding_type: High-level category (open_port, vulnerability, misc_config)
    - finding_value: Specific value or severity
    - capability: Proven capability (password_auth, unauthenticated_access, weak_crypto)
    - risk_level: "enum" (reconnaissance), "exploit" (actionable), "info" (minor)
    """
    id: str
    source_tool: str
    finding_type: str
    target: str

    finding_value: Optional[str] = None
    severity: Optional[str] = None
    capability: Optional[str] = None
    risk_level: Optional[str] = None

    # Canonical fields
    port: Optional[int] = None
    service: Optional[str] = None
    version: Optional[str] = None
    version: Optional[str] = None
    os: Optional[str] = None
    
    # Vulnerability specifics
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    details: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self):
        return (f"Finding(source='{self.source_tool}', type='{self.finding_type}', "
                f"value='{self.finding_value}', cap='{self.capability}', risk='{self.risk_level}', target='{self.target}')")


