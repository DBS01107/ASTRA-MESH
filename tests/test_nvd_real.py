import unittest
import os
from dotenv import load_dotenv

# Load env vars BEFORE importing module that uses them
load_dotenv()

from google_adk.nvd import search_cve

RUN_REAL_NVD_TESTS = os.environ.get("RUN_REAL_NVD_TESTS") == "1"

@unittest.skipUnless(
    RUN_REAL_NVD_TESTS,
    "Set RUN_REAL_NVD_TESTS=1 to run live NVD API tests.",
)
class TestNVDRealIntegration(unittest.TestCase):
    """
    Integration tests that hit the REAL NVD API.
    Requires NVD_API_KEY to be set in environment for best performance.
    """

    @classmethod
    def setUpClass(cls):
        if not os.environ.get("NVD_API_KEY"):
            print("WARNING: NVD_API_KEY not set. Tests may be slow or rate-limited.")

    def test_real_log4shell(self):
        """Log4Shell — CVE-2021-44228"""
        print("\n[*] Fetching Log4Shell...")
        cve_id = "CVE-2021-44228"
        result = search_cve(cve_id)

        self.assertIsNotNone(result)
        self.assertEqual(result["id"], cve_id)

        # CVSS score is the reliable indicator
        self.assertGreaterEqual(result["cvss_score"], 9.0)

        # Exploit references may vary
        self.assertIsInstance(result.get("exploit_references", []), list)

        print(f"[+] {cve_id} OK (Score: {result['cvss_score']})")

    def test_real_eternalblue(self):
        print("\n[*] Fetching EternalBlue...")
        cve_id = "CVE-2017-0144"
        result = search_cve(cve_id)

        self.assertIsNotNone(result)
        self.assertEqual(result["id"], cve_id)

        # Stable check
        self.assertGreaterEqual(result["cvss_score"], 8.0)

        # Description should exist, not match keywords
        self.assertTrue(len(result["description"]) > 20)

        print(f"[+] {cve_id} OK")


    def test_real_heartbleed(self):
        """Heartbleed — CVE-2014-0160"""
        print("\n[*] Fetching Heartbleed...")
        cve_id = "CVE-2014-0160"
        result = search_cve(cve_id)

        self.assertIsNotNone(result)
        self.assertEqual(result["id"], cve_id)

        self.assertIn("openssl", result["description"].lower())
        self.assertGreater(result["cvss_score"], 5.0)

        print(f"[+] {cve_id} OK")


if __name__ == "__main__":
    unittest.main()
