import sys
import unittest
import os
# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from orchestrator.core.parsers import parse_nmap_xml, parse_nuclei_jsonl

class TestCVEParsers(unittest.TestCase):
    def test_nmap_vulners(self):
        findings = parse_nmap_xml("tests/mock_scans/nmap_vulners.xml")
        cve_findings = [f for f in findings if f.finding_type == "vulnerability"]
        
        self.assertTrue(len(cve_findings) > 0, "No CVE findings parsed from Nmap")
        first_cve = cve_findings[0]
        self.assertTrue(first_cve.cve_id.startswith("CVE-"), f"Invalid CVE ID: {first_cve.cve_id}")
        self.assertGreater(first_cve.cvss_score, 0, "CVSS score should be positive")
        print(f"\n[+] Nmap CVE Parsed: {first_cve.cve_id} (Score: {first_cve.cvss_score})")

    def test_nuclei_cve(self):
        findings = parse_nuclei_jsonl("tests/mock_scans/nuclei_cve.jsonl")
        self.assertTrue(len(findings) > 0, "No findings parsed from Nuclei")
        
        finding = findings[0]
        self.assertEqual(finding.cve_id, "CVE-2023-1234")
        self.assertEqual(finding.cvss_score, 9.8)
        self.assertEqual(finding.risk_level, "exploit")
        print(f"\n[+] Nuclei CVE Parsed: {finding.cve_id} (Score: {finding.cvss_score})")

if __name__ == '__main__':
    unittest.main()
