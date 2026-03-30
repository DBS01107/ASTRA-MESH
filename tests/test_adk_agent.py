import sys
import os
import logging

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Configure logging
logging.basicConfig(level=logging.INFO)

from google_adk.agent import ScanAgent
from orchestrator.core.findings import StandardFinding

def test_agent_integration():
    print("[*] Initializing ScanAgent...")
    try:
        agent = ScanAgent()
        print("[+] Agent initialized successfully.")
    except Exception as e:
        print(f"[-] Failed to initialize agent: {e}")
        return

    # Create mock findings with a CVE
    findings = [
        StandardFinding(
            id="test_vuln_1",
            source_tool="mock_tool",
            target="127.0.0.1",
            finding_type="vulnerability",
            finding_value="CVE-2016-10009",
            risk_level="exploit",
            cve_id="CVE-2016-10009",
            cvss_score=9.3,
            details={"description": "Mock serious vulnerability"}
        )
    ]

    print("\n[*] Testing analyze_findings with mock data...")
    try:
        response = agent.analyze_findings(findings)
        print(f"[+] Agent Response:\n{response}")
    except Exception as e:
        print(f"[-] Agent analysis failed: {e}")

if __name__ == "__main__":
    test_agent_integration()
