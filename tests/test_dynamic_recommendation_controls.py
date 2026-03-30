import unittest
from unittest.mock import AsyncMock, patch

from google_adk.agent import ScanAgent
from orchestrator.core import dependencies
from orchestrator.core.findings import StandardFinding
from orchestrator.core import utils


class TestDynamicRecommendationControls(unittest.TestCase):
    @patch.object(ScanAgent, "_run_analysis_async", new_callable=AsyncMock)
    @patch("google_adk.agent.search_exploitdb")
    def test_recommendation_cooldown_skips_repeated_ai_calls(self, mock_search_exploitdb, mock_ai_call):
        mock_search_exploitdb.return_value = []
        mock_ai_call.return_value = '{"reasoning":"ok","recommendations":[{"tool":"nuclei"}]}'

        agent = ScanAgent()
        agent.recommendation_cooldown_seconds = 3600
        agent.recommendation_max_calls_per_session = 10

        findings = [
            StandardFinding(
                id="nmap_port_10_0_0_20_80",
                source_tool="nmap",
                target="http://10.0.0.20",
                finding_type="web_service",
                finding_value="http",
                service="http",
                version="Apache 2.4.7",
                risk_level="exploit",
            )
        ]

        session_id = "cooldown-test"
        agent.recommend_next_scans(findings, executed_tools=[], session_id=session_id)
        agent.recommend_next_scans(findings, executed_tools=[], session_id=session_id)

        self.assertEqual(mock_ai_call.call_count, 1)
        self.assertIn("cooldown", agent.get_latest_reasoning(session_id).lower())

    def test_merge_recommendations_preserves_dynamic_flags(self):
        agent = ScanAgent()
        merged = agent._merge_recommendations(
            deterministic_recommendations=[
                {"tool": "nuclei", "target": "http://10.0.0.8", "flags": "-severity critical,high"}
            ],
            ai_recommendations=[],
            executed_tools=[],
            available_tools=["nuclei"],
        )

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["tool"], "nuclei")
        self.assertEqual(merged[0]["flags"], ["-severity", "critical,high"])

    def test_command_builder_injects_dynamic_flags(self):
        scanner = {
            "name": "nmap",
            "cmd_template": "nmap -sT -sV -oX orchestrator/output/raw/{target}_nmap.xml {target}",
        }
        args = utils.command_builder(
            scanner=scanner,
            display_target="scanme.nmap.org",
            primary_target="scanme.nmap.org",
            output_file="orchestrator/output/raw/scanme.nmap.org_nmap.xml",
            dynamic_flags=["-Pn", "-p", "80"],
        )

        self.assertEqual(args[0], "nmap")
        self.assertEqual(args[1:4], ["-Pn", "-p", "80"])
        self.assertIn("scanme.nmap.org", args)

    @patch.object(ScanAgent, "_run_analysis_async", new_callable=AsyncMock)
    def test_recommendation_reasoning_explicit_when_ai_omits_reasoning(self, mock_ai_call):
        mock_ai_call.return_value = '{"recommendations":[{"tool":"nuclei"}]}'

        agent = ScanAgent()
        session_id = "reasoning-missing-test"
        agent.recommend_next_scans(findings=[], executed_tools=[], session_id=session_id)

        latest_reasoning = agent.get_latest_reasoning(session_id).lower()
        self.assertIn("reasoning was not returned", latest_reasoning)

    @patch.object(ScanAgent, "_run_analysis_async", new_callable=AsyncMock)
    def test_recommendation_reasoning_explicit_when_ai_output_unstructured(self, mock_ai_call):
        mock_ai_call.return_value = "analysis text without json structure"

        agent = ScanAgent()
        session_id = "reasoning-unstructured-test"
        agent.recommend_next_scans(findings=[], executed_tools=[], session_id=session_id)

        latest_reasoning = agent.get_latest_reasoning(session_id).lower()
        self.assertIn("unstructured", latest_reasoning)

    @patch.object(ScanAgent, "_run_analysis_async", new_callable=AsyncMock)
    def test_recommendation_reasoning_mentions_429_when_rate_limited(self, mock_ai_call):
        mock_ai_call.return_value = "429 rate limit exceeded by provider"

        agent = ScanAgent()
        session_id = "reasoning-rate-limit-test"
        agent.recommend_next_scans(findings=[], executed_tools=[], session_id=session_id)

        latest_reasoning = agent.get_latest_reasoning(session_id).lower()
        self.assertIn("429", latest_reasoning)

    def test_nikto_runtime_auto_install_is_disabled(self):
        self.assertNotIn("nikto", dependencies.TOOL_INSTALL_COMMANDS)


if __name__ == "__main__":
    unittest.main()
