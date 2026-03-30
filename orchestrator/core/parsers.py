import os
import json
import xml.etree.ElementTree as ET
from typing import List, Callable, Optional, Dict

from .findings import StandardFinding

# --------------------------------------------------------------------
# 1. Nmap Parser
# --------------------------------------------------------------------
def parse_nmap_xml(file_path: str, target_context: Optional[str] = None) -> List[StandardFinding]:
    """
    Parses Nmap XML output and emits atomic facts with proven capabilities.
    Only emit capability when scanner provides evidence.
    """
    findings = []
    if not os.path.exists(file_path):
        return findings

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for host in root.findall("host"):
            address_element = host.find("address")
            if address_element is None: continue
            
            addr = address_element.get("addr")
            for port in host.findall(".//port"):
                state_element = port.find("state")
                if state_element is None or state_element.get("state") != "open":
                    continue
                
                port_id = int(port.get("portid"))
                service_el = port.find("service")
                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""

                # --- Fact 1: Open Port (reconnaissance, no capability) ---
                findings.append(StandardFinding(
                    id=f"nmap_port_{addr}_{port_id}",
                    source_tool="nmap",
                    target=addr,
                    finding_type="open_port",
                    finding_value=str(port_id),
                    risk_level="enum",
                    capability=None,  # Open port alone proves nothing actionable
                    port=port_id,
                    service=service_name,
                    version=version,
                    details={
                        "service": service_name,
                        "product": product,
                        "version": version
                    }
                ))

                # --- Service-specific capabilities (inferred from nmap data) ---
                
                # SSH: Check for weak crypto indicators
                if "ssh" in service_name.lower():
                    if "OpenSSH 6.6" in product or "OpenSSH 6" in product:
                        findings.append(StandardFinding(
                            id=f"nmap_ssh_weak_{addr}_{port_id}",
                            source_tool="nmap",
                            target=addr,
                            finding_type="service_capability",
                            finding_value="ssh_weak_crypto",
                            risk_level="exploit",
                            capability="weak_crypto",
                            port=port_id,
                            service="ssh",
                            version=version,
                            details={
                                "service": "ssh",
                                "port": port_id,
                                "product": product,
                                "reason": "Known weak crypto"
                            }
                        ))
                
                # --- Fact 2: Web Service (actionable for exploitation) ---
                if "http" in service_name.lower() or port_id in [80, 443, 8000, 8080, 8443]:
                    scheme = "https" if "https" in service_name.lower() or "ssl" in service_name.lower() or port_id in [443, 8443] else "http"
                    url = f"{scheme}://{addr}"
                    if not ((scheme == "http" and port_id == 80) or (scheme == "https" and port_id == 443)):
                        url += f":{port_id}"
                    
                    findings.append(StandardFinding(
                        id=f"nmap_web_service_{addr}_{port_id}",
                        source_tool="nmap",
                        target=url,
                        finding_type="web_service",
                        finding_value=service_name,
                        risk_level="exploit",
                        capability="web_exposed",  # Web service is a proven capability
                        port=port_id,
                        service=service_name,
                        version=version,
                        details={
                            "port": port_id,
                            "product": product,
                            "version": version
                        }
                    ))
                
                # --- Fact 3: Vulnerabilities from scripts (e.g. vulners) ---
                for script in port.findall("script"):
                    if script.get("id") == "vulners":
                        output = script.get("output", "")
                        # Parse vulners text output
                        # Format usually:
                        #   cpe:/a:vendor:product:version: 
                        #     CVE-YYYY-NNNN SC.ORE https://...
                        # Logic to handle XML attribute normalization (where newlines become spaces)
                        # Tokenize everything and look for CVE patterns
                        tokens = output.split()
                        for i, token in enumerate(tokens):
                            if token.startswith("CVE-") or token.startswith("SSV-"):
                                cve_id = token
                                cvss_score = 0.0
                                # Try to grab the next token as the score
                                if i + 1 < len(tokens):
                                    try:
                                        cvss_score = float(tokens[i+1])
                                    except ValueError:
                                        pass
                                
                                findings.append(StandardFinding(
                                    id=f"nmap_vuln_{addr}_{port_id}_{cve_id}",
                                    source_tool="nmap",
                                    target=addr,
                                    finding_type="vulnerability",
                                    finding_value=cve_id,
                                    risk_level="exploit" if cvss_score >= 7.0 else "misconfig",
                                    capability="exploit_available",
                                    port=port_id,
                                    service=service_name,
                                    version=version,
                                    cve_id=cve_id,
                                    cvss_score=cvss_score,
                                    details={
                                        "service": service_name,
                                        "product": product,
                                        "version": version,
                                        "cvss": cvss_score
                                    }
                                ))


    except (ET.ParseError, IOError) as e:
        print(f"[!] Error parsing Nmap XML file {file_path}: {e}")
    return findings

# --------------------------------------------------------------------
# 2. WhatWeb Parser
# --------------------------------------------------------------------
def parse_whatweb_json(file_path: str, target_context: Optional[str] = None) -> List[StandardFinding]:
    """
    Parses WhatWeb's JSON output file.
    The output can be an array of result objects or multiple arrays (from multiple runs).
    The 'target_context' (URL) is used if not provided in the data.
    Enriches findings with risk_level and capability information.
    """
    findings = []
    if not os.path.exists(file_path): return findings
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
        
        # Handle multiple JSON arrays in the file (from multiple whatweb runs)
        # Split by ]\n[ which indicates multiple arrays
        json_objects = []
        if ']\n[' in content:
            # Multiple arrays - process each separately
            parts = content.split(']\n[')
            for i, part in enumerate(parts):
                if i == 0:
                    part = part.lstrip('[')
                else:
                    part = '[' + part
                if i < len(parts) - 1:
                    part = part + ']'
                else:
                    part = part.rstrip(']')
                try:
                    data = json.loads('[' + part + ']') if not (part.startswith('[') and part.endswith(']')) else json.loads(part)
                    if isinstance(data, list):
                        json_objects.extend(data)
                    else:
                        json_objects.append(data)
                except:
                    pass
        else:
            # Single JSON array
            data = json.loads(content)
            if isinstance(data, list):
                json_objects = data
            else:
                json_objects = [data]
        
        # Map known technologies to capabilities and risk levels
        tech_to_capability = {
            "WordPress": "cms_detected",
            "Drupal": "cms_detected",
            "Joomla": "cms_detected",
            "Apache": "web_server_identified",
            "Nginx": "web_server_identified",
            "IIS": "web_server_identified",
            "PHP": "server_side_lang_detected",
            "ASP": "server_side_lang_detected",
            "JSP": "server_side_lang_detected",
            "Node.js": "server_side_lang_detected",
        }
        
        seen_findings = set()
        for result in json_objects:
            target = result.get("target", target_context)
            plugins = result.get("plugins", {})
            for tech_name, details in plugins.items():
                # Skip duplicate findings from multiple runs
                finding_key = (tech_name, target)
                if finding_key in seen_findings:
                    continue
                seen_findings.add(finding_key)
                
                capability = tech_to_capability.get(tech_name, "technology_identified")
                # Technology discovery is typically info-level (not exploitable by itself)
                risk_level = "info"
                
                findings.append(StandardFinding(
                    id=f"whatweb_{tech_name}",
                    source_tool="whatweb",
                    target=target,
                    finding_type="technology",
                    finding_value=tech_name,
                    capability=capability,
                    risk_level=risk_level,
                    details={"version": details.get("version", [])}
                ))
    except (json.JSONDecodeError, IOError) as e:
        print(f"[!] Error parsing WhatWeb JSON file {file_path}: {e}")
    return findings

# --------------------------------------------------------------------
# 3. Nuclei Parser
# --------------------------------------------------------------------
def parse_nuclei_jsonl(file_path: str, target_context: Optional[str] = None) -> List[StandardFinding]:
    """
    Parses Nuclei's JSON Lines (.jsonl) output format.
    Enriches findings with risk_level and capability based on severity.
    """
    findings = []
    if not os.path.exists(file_path): return findings
    try:
        with open(file_path, 'r') as f:
            for line_num, line in enumerate(f):
                data = json.loads(line)
                info = data.get("info", {})
                severity = info.get("severity", "info").lower()
                template_id = data.get("template-id", "unknown")
                
                # Map severity to risk_level and capability
                severity_to_risk = {
                    "critical": "exploit",
                    "high": "exploit",
                    "medium": "enum",
                    "low": "info",
                    "info": "info"
                }
                
                # Map severity to risk_level and capability
                finding_type = info.get("name", "unknown")
                capability = None
                if severity in ["critical", "high"]:
                    capability = "exploitable_vulnerability"
                elif "auth" in finding_type.lower() or "authentication" in template_id.lower():
                    capability = "auth_bypass_detected"
                elif "xss" in template_id.lower():
                    capability = "xss_detected"
                elif "sql" in template_id.lower():
                    capability = "sqli_detected"
                elif "rce" in template_id.lower():
                    capability = "rce_detected"
                elif "apache" in template_id.lower() and "2.4.7" in str(data):
                    capability = "outdated_apache_server"
                    severity = "high"
                    risk_level = "exploit"
                else:
                    capability = "vulnerability_found"
                
                risk_level = severity_to_risk.get(severity, "info")
                
                if "classification" in info:
                    classification = info["classification"]
                    cve_ids = classification.get("cve-id", [])
                    cvss_score = classification.get("cvss-score", 0.0)
                    cvss_metrics = classification.get("cvss-metrics", "")
                else:
                    cve_ids = []
                    cvss_score = 0.0
                    cvss_metrics = ""

                # If multiple CVEs, pick the first one for the main ID, but store all in details
                primary_cve = cve_ids[0] if cve_ids else None
                
                findings.append(StandardFinding(
                    id=f"nuclei_{template_id}_{line_num}",
                    source_tool="nuclei",
                    target=data.get("host"),
                    finding_type="vulnerability",
                    finding_value=primary_cve if primary_cve else template_id,
                    severity=severity,
                    capability=capability,
                    risk_level=risk_level,
                    cve_id=primary_cve,
                    cvss_score=float(cvss_score) if cvss_score else None,
                    cvss_vector=cvss_metrics,
                    details={
                        "name": info.get("name"),
                        "severity": severity,
                        "tags": info.get("tags", []),
                        "cve_ids": cve_ids,
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_metrics
                    }
                ))
    except (json.JSONDecodeError, IOError) as e:
        print(f"[!] Error parsing Nuclei JSONL file {file_path}: {e}")
    return findings


# --------------------------------------------------------------------
# 4. Nikto Parser
# --------------------------------------------------------------------
def parse_nikto_txt(file_path: str, target_context: Optional[str] = None) -> List[StandardFinding]:
    """
    Parses Nikto text output and emits findings with appropriate risk levels.
    Nikto identifies web server misconfigurations and vulnerabilities.
    """
    findings = []
    if not os.path.exists(file_path):
        return findings
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Extract target from context or file content
        target = target_context or ""
        
        # Parse Nikto text output - look for lines with findings
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('+'):
                # Extract target from banner line if not provided
                if 'Target IP' in line or 'Target Host' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        target = parts[-1].strip()
                continue
            
            # Lines with OSVDB entries or findings start with -
            if line.startswith('- '):
                # Parse finding line: - OSVDB-#### (severity) finding_description
                # Example: "- OSVDB-3268 (SUSPICIOUS) /: Directory indexing found."
                finding_parts = line[2:].split(' ', 1)  # Skip "- "
                
                if not finding_parts:
                    continue
                
                osvdb_id = finding_parts[0] if len(finding_parts) > 0 else ""
                rest = finding_parts[1] if len(finding_parts) > 1 else ""
                
                # Extract severity level if enclosed in parentheses
                severity = "info"
                capability = None
                risk_level = "info"
                
                if '(' in rest and ')' in rest:
                    sev_part = rest[rest.index('(')+1:rest.index(')')]
                    severity = sev_part.lower()
                    description = rest[rest.index(')')+1:].strip()
                else:
                    description = rest
                
                # Map Nikto severity/finding types to our capability and risk_level
                if 'cookie' in description.lower() or 'set-cookie' in description.lower():
                    capability = "cookie_handling"
                    risk_level = "enum"
                elif 'ssl' in description.lower() or 'https' in description.lower():
                    capability = "ssl_config"
                    risk_level = "enum"
                elif 'directory' in description.lower() or 'indexing' in description.lower():
                    capability = "directory_traversal"
                    risk_level = "misconfig"
                elif 'authentication' in description.lower() or 'auth' in description.lower():
                    capability = "auth_weakness"
                    risk_level = "misconfig"
                elif 'server' in description.lower() and ('version' in description.lower() or 'header' in description.lower()):
                    capability = "server_disclosure"
                    risk_level = "enum"
                elif 'cgi' in description.lower() or 'executable' in description.lower():
                    capability = "cgi_vulnerability"
                    risk_level = "exploit"
                elif 'vulnerability' in description.lower() or 'vulnerable' in description.lower():
                    capability = "web_vulnerability"
                    risk_level = "exploit"
                elif 'xss' in description.lower() or 'cross' in description.lower():
                    capability = "xss"
                    risk_level = "exploit"
                elif 'injection' in description.lower():
                    capability = "injection"
                    risk_level = "exploit"
                else:
                    capability = "web_config"
                    risk_level = "enum"
                
                if description and target:
                    findings.append(StandardFinding(
                        id=f"nikto_{osvdb_id}_{target}",
                        source_tool="nikto",
                        target=target,
                        finding_type="web_config",
                        finding_value=osvdb_id,
                        severity=severity,
                        capability=capability,
                        risk_level=risk_level,
                        details={"osvdb_id": osvdb_id, "description": description}
                    ))
    
    except (IOError, OSError) as e:
        print(f"[!] Error parsing Nikto text file {file_path}: {e}")
    
    return findings


# --------------------------------------------------------------------
# 6. Enum4Linux Parser
# --------------------------------------------------------------------
def parse_enum4linux(file_path: str, target_context: Optional[str] = None) -> List[StandardFinding]:
    """
    Parses Enum4Linux text output.
    Attempts to extract workgroup/domain info and user lists.
    """
    findings = []
    # If the tool failed (exit code 1) the file might still exist with error output
    if not os.path.exists(file_path):
        return findings

    try:
        with open(file_path, 'r') as f:
            content = f.read()
            
        target = target_context or "unknown"
        
        # Look for Workgroup/Domain
        if "Got domain/workgroup name:" in content:
            # Parse it out
            pass # TODO: Regex extraction
            
        # For now, just a placeholder if it ran successfully
        if "Enumerating Workgroup/Domain" in content:
            pass

    except Exception as e:
        print(f"[!] Error parsing Enum4Linux: {e}")
        
    return findings

# --------------------------------------------------------------------
# 5. The Parser Dispatcher (The Brain's Librarian)
# --------------------------------------------------------------------
# This mapping allows the engine to dynamically select the correct parser.
PARSER_MAPPING: Dict[str, Callable] = {
    "nmap": parse_nmap_xml,
    "nmap-ssh-scripts": parse_nmap_xml,
    "nmap-ftp-scripts": parse_nmap_xml,
    "nmap-smb-scripts": parse_nmap_xml,
    "whatweb": parse_whatweb_json,
    "nuclei": parse_nuclei_jsonl,
    "nikto": parse_nikto_txt,
    "vulners": parse_nmap_xml,
    "enum4linux": parse_enum4linux,
}

def get_parser_for_tool(tool_name: str) -> Optional[Callable]:
    """
    Given a tool's name, this function returns the corresponding parser function.
    Returns None if no parser is defined for the tool.
    """
    return PARSER_MAPPING.get(tool_name)

