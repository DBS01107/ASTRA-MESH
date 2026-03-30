import argparse
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Sequence, Set

COMMON_PORTS = "22,23,80,443,554,8000,8080,8443,8888,9000,1883,5683"
TLS_LIKE_PORTS = {443, 465, 853, 993, 995, 8443, 8883}
SSH_PORT = 22

WEAK_TLS_MARKERS = {
    "tlsv1.0": ("Legacy TLS 1.0 enabled", "high"),
    "tlsv1.1": ("Legacy TLS 1.1 enabled", "medium"),
    "3des": ("Weak TLS cipher detected (3DES)", "high"),
    "rc4": ("Weak TLS cipher detected (RC4)", "high"),
    "md5": ("Weak TLS hash/signature detected (MD5)", "high"),
    "null": ("NULL TLS cipher detected", "high"),
    "export": ("Export-grade TLS cipher detected", "high"),
    "des-cbc": ("Weak TLS cipher detected (DES-CBC)", "high"),
}

WEAK_SSH_MARKERS = {
    "diffie-hellman-group1-sha1": ("Weak SSH KEX detected (group1-sha1)", "high"),
    "diffie-hellman-group14-sha1": ("Legacy SSH KEX detected (group14-sha1)", "medium"),
    "ssh-dss": ("Weak SSH host key algorithm detected (ssh-dss)", "high"),
    "hmac-md5": ("Weak SSH MAC detected (hmac-md5)", "high"),
    "cbc": ("SSH CBC cipher detected", "medium"),
}


def run_nmap(args: Sequence[str]) -> str:
    cmd = ["nmap"] + list(args)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap failed: {proc.stderr.decode().strip()}")
    return proc.stdout.decode()


def _parse_host_identity(host_el: ET.Element) -> Dict:
    ip = None
    mac = None
    vendor = None
    for addr in host_el.findall("address"):
        addr_type = (addr.get("addrtype") or "").lower()
        if addr_type == "ipv4":
            ip = addr.get("addr")
        elif addr_type == "mac":
            mac = addr.get("addr")
            vendor = addr.get("vendor")

    if ip is None:
        first_addr = host_el.find("address")
        if first_addr is not None:
            ip = first_addr.get("addr")

    name_el = host_el.find("hostnames/hostname")
    name = name_el.get("name") if name_el is not None else None
    return {"ip": ip, "name": name, "mac": mac, "vendor": vendor}


def discover_hosts(subnet: str) -> List[Dict]:
    """Perform a ping scan (ARP/ICMP) and return discovered hosts."""
    out = run_nmap(["-sn", "-oX", "-", subnet])
    root = ET.fromstring(out)
    hosts = []
    for host in root.findall("host"):
        identity = _parse_host_identity(host)
        if not identity.get("ip"):
            continue
        hosts.append(identity)
    return hosts


def _parse_service_scan(out: str) -> List[Dict]:
    root = ET.fromstring(out)
    services = []
    for port in root.findall(".//port"):
        portid = port.get("portid")
        proto = port.get("protocol")
        state_el = port.find("state")
        state = state_el.get("state") if state_el is not None else "unknown"
        service_el = port.find("service")
        service = service_el.get("name") if service_el is not None else None

        if service_el is not None:
            product = service_el.get("product") or ""
            version = service_el.get("version") or ""
            extrainfo = service_el.get("extrainfo") or ""
            service_version = " ".join(
                part for part in [product, version, extrainfo] if part
            ).strip()
        else:
            service_version = ""

        services.append(
            {
                "port": int(portid) if portid else None,
                "proto": proto,
                "state": state,
                "service": service,
                "version": service_version,
            }
        )
    return services


def _candidate_crypto_ports(services: List[Dict]) -> Set[int]:
    ports = set()
    for svc in services:
        if svc.get("state") != "open":
            continue
        port = svc.get("port")
        service_name = (svc.get("service") or "").lower()
        if not isinstance(port, int):
            continue
        if port == SSH_PORT:
            ports.add(port)
            continue
        if port in TLS_LIKE_PORTS:
            ports.add(port)
            continue
        if any(token in service_name for token in ("https", "ssl", "tls")):
            ports.add(port)
    return ports


def _append_unique_issue(findings: List[Dict], issue: Dict):
    key = (issue.get("port"), issue.get("type"), issue.get("issue"))
    for existing in findings:
        if (existing.get("port"), existing.get("type"), existing.get("issue")) == key:
            return
    findings.append(issue)


def _parse_ssl_issues(port: int, output: str) -> List[Dict]:
    findings: List[Dict] = []
    out_l = output.lower()
    for marker, (issue_text, severity) in WEAK_TLS_MARKERS.items():
        if marker in out_l:
            _append_unique_issue(
                findings,
                {
                    "port": port,
                    "type": "tls",
                    "issue": issue_text,
                    "severity": severity,
                    "evidence": marker,
                },
            )

    grade_match = re.search(r"least strength:\s*([A-F])", output, flags=re.I)
    if grade_match:
        grade = grade_match.group(1).upper()
        if grade in {"C", "D", "E", "F"}:
            _append_unique_issue(
                findings,
                {
                    "port": port,
                    "type": "tls",
                    "issue": f"Weak TLS cipher grade ({grade})",
                    "severity": "high",
                    "evidence": f"least strength: {grade}",
                },
            )
        elif grade == "B":
            _append_unique_issue(
                findings,
                {
                    "port": port,
                    "type": "tls",
                    "issue": "Suboptimal TLS cipher grade (B)",
                    "severity": "medium",
                    "evidence": "least strength: B",
                },
            )
    return findings


def _parse_ssh_issues(port: int, output: str) -> List[Dict]:
    findings: List[Dict] = []
    out_l = output.lower()
    for marker, (issue_text, severity) in WEAK_SSH_MARKERS.items():
        if marker in out_l:
            _append_unique_issue(
                findings,
                {
                    "port": port,
                    "type": "ssh",
                    "issue": issue_text,
                    "severity": severity,
                    "evidence": marker,
                },
            )
    return findings


def scan_crypto_findings(ip: str, services: List[Dict]) -> List[Dict]:
    ports = _candidate_crypto_ports(services)
    if not ports:
        return []
    out = run_nmap(
        [
            "-Pn",
            "-p",
            ",".join(str(p) for p in sorted(ports)),
            "--script",
            "ssl-enum-ciphers,ssh2-enum-algos",
            "-oX",
            "-",
            ip,
        ]
    )
    root = ET.fromstring(out)
    findings: List[Dict] = []
    for port_el in root.findall(".//port"):
        portid = port_el.get("portid")
        state_el = port_el.find("state")
        state = state_el.get("state") if state_el is not None else "unknown"
        if state != "open" or not portid:
            continue
        port_num = int(portid)
        for script in port_el.findall("script"):
            script_id = script.get("id") or ""
            output = script.get("output") or ""
            if script_id == "ssl-enum-ciphers":
                findings.extend(_parse_ssl_issues(port_num, output))
            elif script_id == "ssh2-enum-algos":
                findings.extend(_parse_ssh_issues(port_num, output))
    return findings


def scan_host_services(
    host: Dict, ports: str = COMMON_PORTS, enable_crypto_checks: bool = True
) -> Dict:
    """Scan common ports/services for a single host and include crypto checks."""
    ip = host.get("ip")
    if not ip:
        raise ValueError("host object is missing 'ip'")
    out = run_nmap(["-Pn", "-sV", "-p", ports, "-oX", "-", ip])
    services = _parse_service_scan(out)
    result = {
        "ip": ip,
        "name": host.get("name"),
        "mac": host.get("mac"),
        "vendor": host.get("vendor"),
        "services": services,
    }
    if enable_crypto_checks:
        try:
            result["crypto_findings"] = scan_crypto_findings(ip, services)
        except Exception as exc:
            result["crypto_findings"] = []
            result["crypto_scan_error"] = str(exc)
    return result


def full_discovery(
    subnet: str,
    max_workers: int = 20,
    ports: str = COMMON_PORTS,
    enable_crypto_checks: bool = True,
) -> List[Dict]:
    hosts = discover_hosts(subnet)
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [
            ex.submit(scan_host_services, host, ports, enable_crypto_checks)
            for host in hosts
        ]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"error": str(exc)})
    return results


def discovery_to_json(results: List[Dict], outpath: str):
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "devices": results,
    }
    with open(outpath, "w") as f:
        json.dump(payload, f, indent=2)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("subnet", help="target subnet, e.g. 192.168.1.0/24")
    p.add_argument("--out", default="iot_scan_discovery.json")
    p.add_argument("--ports", default=COMMON_PORTS, help="comma-separated port list")
    p.add_argument("--max-workers", type=int, default=20)
    p.add_argument(
        "--no-crypto-checks",
        action="store_true",
        help="disable TLS/SSH weak-encryption checks",
    )
    args = p.parse_args()
    res = full_discovery(
        args.subnet,
        max_workers=args.max_workers,
        ports=args.ports,
        enable_crypto_checks=not args.no_crypto_checks,
    )
    discovery_to_json(res, args.out)
