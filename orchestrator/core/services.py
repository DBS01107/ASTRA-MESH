import xml.etree.ElementTree as ET
from typing import Dict, List

def parse_nmap_services(file_path: str) -> Dict[str, List[str]]:
    """
    Parses an Nmap XML file and returns a dictionary:
    {
        "http": [list of http://... URLs],
        "https": [list of https://... URLs],
        "all": [list of host:port/proto]
    }
    """
    result = {
        "http": [],
        "https": [],
        "all": [],
    }

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for host in root.findall("host"):
            addr_el = host.find("address")
            if addr_el is None:
                continue
            addr = addr_el.get("addr", "unknown")

            for port in host.findall("ports/port"):
                portid = port.get("portid")
                proto = port.get("protocol")
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                # Add to 'all'
                result["all"].append(f"{addr}:{portid}/{proto}")

                # Detect service type
                service_el = port.find("service")
                service_name = service_el.get("name", "").lower() if service_el is not None else ""

                # Very basic HTTP/HTTPS detection
                if "https" in service_name or ("http" in service_name and "ssl" in service_name):
                    if portid == "443":
                        url = f"https://{addr}"
                    else:
                        url = f"https://{addr}:{portid}"
                    result["https"].append(url)
                elif "http" in service_name:
                    if portid == "80":
                        url = f"http://{addr}"
                    else:
                        url = f"http://{addr}:{portid}"
                    result["http"].append(url)

    except Exception as e:
        print(f"[!] Failed parsing nmap XML: {e}")

    return result

