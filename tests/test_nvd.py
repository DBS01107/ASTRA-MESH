
import unittest
from unittest.mock import patch, MagicMock
from google_adk.nvd import NVDClient, search_cve

class TestNVDClient(unittest.TestCase):
    def setUp(self):
        self.mock_nvd_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2017-0144",
                        "descriptions": [
                            {"lang": "en", "value": "EternalBlue vulnerability in SMBv1."}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 9.8,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                        "baseSeverity": "CRITICAL"
                                    }
                                }
                            ]
                        },
                        "references": [
                            {"url": "https://github.com/misterch0c/shadowbroker", "tags": ["Exploit"]},
                            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144", "tags": ["Vendor Advisory"]}
                        ]
                    }
                }
            ]
        }

    def test_nvd_get_cve_details_success(self):
        with patch("requests.get") as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = self.mock_nvd_response
            
            client = NVDClient()
            client.delay = 0 
            
            result = client.get_cve_details("CVE-2017-0144")
            
            self.assertIsNotNone(result)
            self.assertEqual(result["id"], "CVE-2017-0144")
            self.assertEqual(result["description"], "EternalBlue vulnerability in SMBv1.")
            self.assertEqual(result["cvss_score"], 9.8)
            self.assertEqual(result["severity"], "CRITICAL")
            self.assertIn("https://github.com/misterch0c/shadowbroker", result["exploit_references"])

    def test_nvd_get_cve_details_not_found(self):
        with patch("requests.get") as mock_get:
            mock_get.return_value.status_code = 404
            
            client = NVDClient()
            client.delay = 0
            result = client.get_cve_details("CVE-9999-9999")
            
            self.assertIsNone(result)

    def test_search_cve_wrapper(self):
        with patch("google_adk.nvd.nvd_client.get_cve_details") as mock_method:
            mock_method.return_value = {"id": "CVE-TEST"}
            result = search_cve("CVE-TEST")
            self.assertEqual(result, {"id": "CVE-TEST"})
            mock_method.assert_called_once_with("CVE-TEST")

if __name__ == "__main__":
    unittest.main()
