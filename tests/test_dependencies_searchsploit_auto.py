import unittest

from orchestrator.core import dependencies


class TestSearchsploitAutoEnable(unittest.TestCase):
    def test_searchsploit_auto_enabled_for_nmap_selection(self):
        enabled = dependencies.resolve_enabled_scanners("nmap")
        self.assertIn("nmap", enabled)
        self.assertIn("searchsploit", enabled)

    def test_searchsploit_auto_enabled_for_whatweb_selection(self):
        enabled = dependencies.resolve_enabled_scanners("whatweb")
        # whatweb depends on nmap and should also auto-enable searchsploit.
        self.assertIn("nmap", enabled)
        self.assertIn("whatweb", enabled)
        self.assertIn("searchsploit", enabled)

    def test_searchsploit_present_in_all(self):
        enabled = dependencies.resolve_enabled_scanners("all")
        self.assertIn("searchsploit", enabled)


if __name__ == "__main__":
    unittest.main()
