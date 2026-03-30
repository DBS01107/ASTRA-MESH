

class ScanTools:
    @staticmethod
    def get_cve_details(cve_id: str) -> str:
        """
        Fetches details for a given CVE ID from NVD (National Vulnerability Database).
        """
        from .nvd import search_cve
        
        result = search_cve(cve_id)
        if not result:
            return f"No details found for {cve_id} in NVD."
        
        summary = f"Details for {cve_id}:\n"
        summary += f"Severity: {result.get('severity')} (Score: {result.get('cvss_score')})\n"
        summary += f"Description: {result.get('description')}\n"
        
        exploits = result.get('exploit_references', [])
        if exploits:
            summary += f"\nPotential Exploit References ({len(exploits)} found):\n"
            for ref in exploits[:5]:  # Limit to 5
                summary += f"- {ref}\n"
        else:
            summary += "\nNo known exploit references found in NVD data.\n"
            
        return summary

    @staticmethod
    def recommend_tool_command(service: str, port: int) -> str:
        """
        Suggests a command to run based on the service.
        """
        service = service.lower()
        if "ssh" in service:
            return f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET:{port}"
        elif "http" in service or "https" in service:
            return f"nikto -h http://TARGET:{port}"
        elif "ftp" in service:
            return f"nmap -p {port} --script ftp-anon,ftp-brute TARGET"
        elif "smb" in service:
            return f"enum4linux -a TARGET"
        else:
            return f"nmap -sV -sC -p {port} TARGET"

    @staticmethod
    def suggest_scan(target: str, scan_type: str, reason: str) -> str:
        """
        Suggests a follow-up scan for a target.
        """
        # In a real system, this would queue a job
        print(f"[AGENT RECOMMENDATION] Run {scan_type} on {target}. Reason: {reason}")
        return f"Suggestion logged: Run {scan_type} on {target}."

    @staticmethod
    def add_attack_node(type: str, value: str, parent_id: str) -> str:
        """
        Adds a node to the attack graph (e.g., 'technique' or 'impact').
        Connects it to a parent node (finding ID or other node ID).
        """
        from orchestrator.core import state
        try:
            session_graph = state.get_graph_for_current_session()
            session_graph.add_attack_node(type, value, parent_id)
            return f"Added {type} node '{value}' connected to {parent_id}."
        except Exception as e:
            return f"Failed to add node: {e}"
