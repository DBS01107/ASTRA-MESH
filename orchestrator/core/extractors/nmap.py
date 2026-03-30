from .base import SemanticExtractor
from core.capabilities import CapabilityFact

class NmapExtractor(SemanticExtractor):
    tool_name = "nmap"

    def extract(self, findings):
        facts = []

        for f in findings:
            # SSH surface
            if f.finding_type == "open_port" and f.port == 22:
                capabilities.append(
                    CapabilityFact(
                        capability="ssh_auth_surface",
                        target=f.target,
                        source_tool="nmap"
                    )
                )


            # Web surface
            if f.finding_type == "open_port" and f.port in (80, 443):
                facts.append(CapabilityFact(
                    capability="web_attack_surface",
                    target=f"http://{f.target}",
                    evidence=f"Web port {f.port} open",
                    confidence=0.9,
                    attributes={
                        "port": f.port,
                        "tls": f.port == 443
                    },
                    source_tool="nmap"
                ))

            # OS detection
            if f.finding_type == "os_detected":
                if "linux" in f.finding_value.lower():
                    facts.append(CapabilityFact(
                        capability="linux_host",
                        target=f.target,
                        evidence=f.finding_value,
                        confidence=0.8,
                        attributes={},
                        source_tool="nmap"
                    ))

        return facts
