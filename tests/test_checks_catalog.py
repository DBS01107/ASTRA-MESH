import unittest

from orchestrator.core.checks_catalog import CHECK_DEFINITIONS, evaluate_check_coverage
from orchestrator.core.findings import StandardFinding


class TestChecksCatalog(unittest.TestCase):
    def test_catalog_contains_full_requested_checklist(self):
        # 18 general + 17 passive + 27 active from the expanded checklist.
        self.assertEqual(len(CHECK_DEFINITIONS), 62)

    def test_detected_status_is_set_from_finding_keywords(self):
        findings = [
            StandardFinding(
                id="f-1",
                source_tool="nuclei",
                target="http://example.com",
                finding_type="vulnerability",
                finding_value="template-x",
                details={"tags": ["sqli", "cve"]},
            )
        ]
        payload = evaluate_check_coverage(["nuclei"], findings=findings)
        sqli_check = next(item for item in payload["checks"] if item["name"] == "SQL Injection")
        self.assertEqual(sqli_check["status"], "detected")

    def test_uncovered_status_is_set_when_no_mapped_scanner_selected(self):
        payload = evaluate_check_coverage([], findings=[])
        uncovered = [item for item in payload["checks"] if item["status"] == "uncovered"]
        self.assertTrue(len(uncovered) > 0)


if __name__ == "__main__":
    unittest.main()
