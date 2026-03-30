
import unittest
from unittest.mock import MagicMock, patch
from orchestrator.core.graph import AstraGraph
from google_adk.tools import ScanTools

class TestADKGraph(unittest.TestCase):
    def setUp(self):
        # Reset local graph state to keep tests deterministic.
        self.graph = AstraGraph()
        self.graph.g.clear()
        self.graph.g.add_node("finding_123", type="finding")
        
    def test_add_attack_node_tool(self):
        print("\n[*] Testing add_attack_node tool...")
        # Mock the Neo4j driver to avoid real connection errors during unit test
        with patch.object(self.graph, '_run_query') as mock_query:
            result = ScanTools.add_attack_node("technique", "Credential Dumping", "finding_123")
            print(f"[+] Tool Output: {result}")
            
            # Check if local graph updated
            self.assertTrue(self.graph.g.has_node("technique:Credential Dumping"))
            self.assertTrue(self.graph.g.has_edge("finding_123", "technique:Credential Dumping"))
            
    def test_suggest_scan_tool(self):
        print("\n[*] Testing suggest_scan tool...")
        result = ScanTools.suggest_scan("192.168.1.1", "Nikto", "Port 80 Open")
        self.assertIn("Suggestion logged", result)
        print(f"[+] Tool Output: {result}")

if __name__ == "__main__":
    unittest.main()
