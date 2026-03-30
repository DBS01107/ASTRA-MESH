import unittest
from unittest.mock import AsyncMock, patch

from google_adk.agent import ScanAgent
from orchestrator.core.findings import StandardFinding


class TestSearchsploitGuidance(unittest.TestCase):
    @patch.object(ScanAgent, "_run_analysis_async", new_callable=AsyncMock)
    @patch("google_adk.agent.search_exploitdb")
    def test_searchsploit_runs_when_all_service_versions_known(self, mock_search_exploitdb, mock_ai_call):
        mock_ai_call.return_value = '{"reasoning":"ok","recommendations":[]}'
        mock_search_exploitdb.return_value = [
            {
                "title": "OpenSSH 7.2p2 - User Enumeration",
                "path": "linux/remote/45233.py",
            }
        ]

        findings = [
            StandardFinding(
                id="nmap_port_10_0_0_5_22",
                source_tool="nmap",
                target="10.0.0.5",
                finding_type="open_port",
                finding_value="22",
                service="ssh",
                version="OpenSSH 7.2p2",
                risk_level="enum",
            )
        ]

        agent = ScanAgent()
        recommendations = agent.recommend_next_scans(findings, executed_tools=[])

        mock_search_exploitdb.assert_called_once_with(software="ssh", version="openssh 7.2p2")
        self.assertTrue(any(rec.get("tool") == "nmap-ssh-scripts" for rec in recommendations))
        self.assertIn("SearchSploit", agent.get_latest_reasoning())

    @patch.object(ScanAgent, "_run_analysis_async", new_callable=AsyncMock)
    @patch("google_adk.agent.search_exploitdb")
    def test_searchsploit_deferred_when_service_version_missing(self, mock_search_exploitdb, mock_ai_call):
        mock_ai_call.return_value = '{"reasoning":"ok","recommendations":[]}'

        findings = [
            StandardFinding(
                id="nmap_port_10_0_0_9_21",
                source_tool="nmap",
                target="10.0.0.9",
                finding_type="open_port",
                finding_value="21",
                service="ftp",
                version="",
                risk_level="enum",
            )
        ]

        agent = ScanAgent()
        recommendations = agent.recommend_next_scans(findings, executed_tools=[])

        mock_search_exploitdb.assert_not_called()
        self.assertTrue(
            all(
                "SearchSploit matched" not in (rec.get("reason", "") or "")
                for rec in recommendations
            )
        )

    @patch.object(ScanAgent, "_run_analysis_async", new_callable=AsyncMock)
    @patch("google_adk.agent.search_exploitdb")
    def test_searchsploit_runs_for_fingerprinted_technologies(self, mock_search_exploitdb, mock_ai_call):
        mock_ai_call.return_value = '{"reasoning":"ok","recommendations":[]}'
        mock_search_exploitdb.return_value = [
            {
                "title": "WordPress Plugin - Remote Code Execution",
                "path": "php/webapps/99999.txt",
                "edb_id": "99999",
            }
        ]

        findings = [
            StandardFinding(
                id="whatweb_wordpress",
                source_tool="whatweb",
                target="http://example.com",
                finding_type="technology",
                finding_value="WordPress",
                risk_level="info",
                details={"version": ["6.4.2"]},
            )
        ]

        agent = ScanAgent()
        recommendations = agent.recommend_next_scans(findings, executed_tools=[])

        mock_search_exploitdb.assert_called_once_with(software="wordpress", version="6.4.2")
        self.assertTrue(any(rec.get("tool") == "wpscan" for rec in recommendations))
        self.assertIn("SearchSploit", agent.get_latest_reasoning())


if __name__ == "__main__":
    unittest.main()
