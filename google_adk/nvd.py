import requests
import os
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

class NVDClient:
    def __init__(self):
        self.api_key = os.environ.get("NVD_API_KEY")
        # NVD Rate limits:
        # Without key: 5 requests in a rolling 30 seconds window (effectively ~6s per request to be safe)
        # With key: 50 requests in a rolling 30 seconds window (effectively ~0.6s per request)
        self.delay = 0.6 if self.api_key else 6.0
        self.last_request_time = 0

    def _wait_for_rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)

    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetches details for a specific CVE ID from the NVD API.
        
        Args:
            cve_id: The CVE ID (e.g., CVE-2023-1234).
            
        Returns:
            A dictionary containing processed CVE details, or None if not found/error.
        """
        self._wait_for_rate_limit()
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
            
        params = {"cveId": cve_id}
        
        try:
            response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=10)
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    return None
                
                cve_item = vulnerabilities[0].get("cve", {})
                return self._parse_cve_data(cve_item)
            elif response.status_code == 404:
                logger.warning(f"CVE {cve_id} not found in NVD.")
                return None
            else:
                logger.error(f"NVD API error for {cve_id}: {response.status_code} - {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to fetch NVD data for {cve_id}: {e}")
            return None

    def _parse_cve_data(self, cve_item: Dict[str, Any]) -> Dict[str, Any]:
        """Parses raw NVD CVE data into a simplified format."""
        
        # 1. Description
        descriptions = cve_item.get("descriptions", [])
        description = "No description available."
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value")
                break
                
        # 2. Metrics (CVSS)
        metrics = cve_item.get("metrics", {})
        cvss_score = "N/A"
        cvss_vector = "N/A"
        severity = "UNKNOWN"
        
        # Try V3.1, then V3.0, then V2.0
        if "cvssMetricV31" in metrics:
            data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = data.get("baseScore", "N/A")
            cvss_vector = data.get("vectorString", "N/A")
            severity = data.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV30" in metrics:
            data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = data.get("baseScore", "N/A")
            cvss_vector = data.get("vectorString", "N/A")
            severity = data.get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV2" in metrics:
            data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score = data.get("baseScore", "N/A")
            cvss_vector = data.get("vectorString", "N/A")
            severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")

        # 3. References (Exploits)
        references = cve_item.get("references", [])
        exploit_links = []
        for ref in references:
            tags = ref.get("tags", [])
            url = ref.get("url", "")
            # Check if it's tagged as exploit or has typical exploit sites
            if "Exploit" in tags or "exploit" in url.lower() or "github" in url.lower() or "packetstorm" in url.lower():
                exploit_links.append(url)
                
        return {
            "id": cve_item.get("id"),
            "description": description,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "exploit_references": exploit_links
        }

# Global instance for easy use
nvd_client = NVDClient()

def search_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Public interface to search for a CVE."""
    return nvd_client.get_cve_details(cve_id)
