import unittest

from orchestrator.core.findings import StandardFinding
from orchestrator.core.rules_engine import evaluate_findings


class TestRulesEngineCompatibility(unittest.TestCase):
    def test_new_schema_triggers_action(self):
        finding = StandardFinding(
            id="f-1",
            source_tool="nmap",
            target="http://example.com",
            finding_type="web_service",
            finding_value="http",
            risk_level="exploit",
        )

        rule = {
            "source_tool": "nmap",
            "triggers": [
                {"field": "finding_type", "match_type": "equals", "value": "web_service"},
                {"field": "finding_value", "match_type": "contains", "value": "http"},
            ],
            "action": {"tool_to_run": "nikto", "target_type": "url_of_finding"},
        }

        actions = evaluate_findings([finding], [rule])
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["tool_to_run"], "nikto")
        self.assertEqual(actions[0]["target"], "http://example.com")

    def test_legacy_when_then_schema_is_supported(self):
        finding = StandardFinding(
            id="f-2",
            source_tool="nuclei",
            target="10.0.0.5",
            finding_type="ssh_auth",
            finding_value="password_auth_enabled",
            service="ssh",
            risk_level="misconfig",
        )

        rule = {
            "when": {
                "finding_type": "ssh_auth",
                "service": "ssh",
                "contains": "password",
            },
            "then": {"tool_to_run": "nmap-ssh-scripts"},
        }

        actions = evaluate_findings([finding], [rule])
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["tool_to_run"], "nmap-ssh-scripts")
        self.assertEqual(actions[0]["target"], "10.0.0.5")

    def test_source_tool_is_enforced_when_defined(self):
        finding = StandardFinding(
            id="f-3",
            source_tool="nmap",
            target="http://example.com",
            finding_type="technology",
            finding_value="WordPress",
        )

        rule = {
            "source_tool": "whatweb",
            "triggers": [
                {"field": "finding_type", "match_type": "equals", "value": "technology"},
            ],
            "action": {"tool_to_run": "wpscan"},
        }

        self.assertEqual(evaluate_findings([finding], [rule]), [])

    def test_cve_target_type_uses_cve_id(self):
        finding = StandardFinding(
            id="f-4",
            source_tool="nuclei",
            target="http://example.com",
            finding_type="vulnerability",
            finding_value="CVE-2025-1111",
            cve_id="CVE-2025-1111",
        )

        rule = {
            "triggers": [
                {"field": "finding_type", "match_type": "equals", "value": "vulnerability"},
            ],
            "action": {"tool_to_run": "searchsploit", "target_type": "cve_of_finding"},
        }

        actions = evaluate_findings([finding], [rule])
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["target"], "CVE-2025-1111")


if __name__ == "__main__":
    unittest.main()

