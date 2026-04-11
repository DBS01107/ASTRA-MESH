import json
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Tuple

VULN_DB_PATH = "iot_scanner/vuln_db.json"
DEFAULT_SIGHTINGS_PATH = "iot_scanner/device_sightings.json"

_RISK_FLAG_WEIGHTS = {
    "default_creds": 2.0,
    "telnet_open": 1.5,
    "weak_encryption": 1.2,
    "unauthorized_device": 2.5,
    "new_device": 0.7,
}

_CRYPTO_SEVERITY_WEIGHTS = {
    "high": 0.8,
    "medium": 0.4,
    "low": 0.2,
}

_PROTOCOL_SEVERITY_WEIGHTS = {
    "critical": 1.5,
    "high": 0.8,
    "medium": 0.4,
    "low": 0.2,
}


def load_vuln_db(path: str = VULN_DB_PATH) -> List[Dict]:
    with open(path, "r") as f:
        return json.load(f)


def _normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    return mac.strip().lower().replace("-", ":")


def load_baseline(path: str = "") -> Dict:
    if not path or not os.path.exists(path):
        return {"enabled": False, "allowed_ips": set(), "allowed_macs": set(), "allowed_pairs": set()}

    with open(path, "r") as f:
        raw = json.load(f)

    allowed_ips = set(raw.get("allowed_ips", []))
    allowed_macs = {_normalize_mac(mac) for mac in raw.get("allowed_macs", []) if mac}
    allowed_pairs = set()
    for entry in raw.get("allowed_devices", []):
        ip = entry.get("ip")
        mac = _normalize_mac(entry.get("mac"))
        if ip or mac:
            allowed_pairs.add((ip, mac))
            if ip:
                allowed_ips.add(ip)
            if mac:
                allowed_macs.add(mac)

    return {
        "enabled": True,
        "allowed_ips": allowed_ips,
        "allowed_macs": allowed_macs,
        "allowed_pairs": allowed_pairs,
    }


def load_sightings(path: str = DEFAULT_SIGHTINGS_PATH) -> Dict:
    if not path or not os.path.exists(path):
        return {"devices": {}}
    with open(path, "r") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        return {"devices": {}}
    data.setdefault("devices", {})
    return data


def save_sightings(data: Dict, path: str = DEFAULT_SIGHTINGS_PATH):
    if not path:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _device_tracking_key(device: Dict) -> str:
    mac = _normalize_mac(device.get("mac", ""))
    if mac:
        return f"mac:{mac}"
    ip = device.get("ip", "")
    return f"ip:{ip}" if ip else "unknown"


def update_sighting(device: Dict, sightings: Dict) -> Tuple[bool, Dict]:
    now = datetime.now(timezone.utc).isoformat()
    devices = sightings.setdefault("devices", {})
    key = _device_tracking_key(device)
    existing = devices.get(key)
    if existing is None:
        entry = {
            "ip": device.get("ip"),
            "mac": _normalize_mac(device.get("mac", "")),
            "vendor": device.get("vendor"),
            "first_seen": now,
            "last_seen": now,
            "seen_count": 1,
        }
        devices[key] = entry
        return True, entry

    existing["last_seen"] = now
    existing["seen_count"] = int(existing.get("seen_count", 0)) + 1
    if device.get("ip"):
        existing["ip"] = device.get("ip")
    if device.get("vendor"):
        existing["vendor"] = device.get("vendor")
    if device.get("mac"):
        existing["mac"] = _normalize_mac(device.get("mac"))
    return False, existing


def evaluate_access_flags(device: Dict, baseline: Dict, first_seen: bool) -> Tuple[Dict, List[str]]:
    flags: Dict = {}
    reasons: List[str] = []
    ip = device.get("ip")
    mac = _normalize_mac(device.get("mac", ""))

    if first_seen:
        flags["new_device"] = True
        reasons.append("Device observed for the first time on this network")

    if baseline.get("enabled"):
        allowed = False
        if ip and ip in baseline.get("allowed_ips", set()):
            allowed = True
        if mac and mac in baseline.get("allowed_macs", set()):
            allowed = True
        if (ip, mac) in baseline.get("allowed_pairs", set()):
            allowed = True
        if not allowed:
            flags["unauthorized_device"] = True
            reasons.append("Device is not present in baseline allowlist")

    return flags, reasons


def match_vulns(services: List[Dict], vuln_db: List[Dict]) -> List[Dict]:
    matches = []
    for s in services:
        svc = s.get("service") or ""
        version = (s.get("version") or "").strip()
        for entry in vuln_db:
            if entry.get("service") and svc and svc.lower() == entry["service"].lower():
                ver_regex = entry.get("version_regex")
                if not ver_regex or (version and re.search(ver_regex, version, re.I)):
                    matches.append(
                        {
                            "port": s.get("port"),
                            "service": svc,
                            "version": version,
                            "cve": entry.get("cve"),
                            "cvss": entry.get("cvss", 0.0),
                            "desc": entry.get("desc", ""),
                        }
                    )
    return matches


def compute_risk(matches: List[Dict], extra_flags: Dict = None, crypto_findings: List[Dict] = None, protocol_findings: List[Dict] = None) -> float:
    if extra_flags is None:
        extra_flags = {}
    if crypto_findings is None:
        crypto_findings = []
    if protocol_findings is None:
        protocol_findings = []

    max_cvss = 0.0
    for m in matches:
        try:
            c = float(m.get("cvss", 0.0))
            if c > max_cvss:
                max_cvss = c
        except Exception:
            continue

    penalty = 0.0
    for flag, weight in _RISK_FLAG_WEIGHTS.items():
        if extra_flags.get(flag):
            penalty += weight

    crypto_penalty = 0.0
    for finding in crypto_findings:
        severity = (finding.get("severity") or "low").lower()
        crypto_penalty += _CRYPTO_SEVERITY_WEIGHTS.get(severity, 0.2)
    penalty += min(2.0, crypto_penalty)

    protocol_penalty = 0.0
    for finding in protocol_findings:
        severity = (finding.get("severity") or "high").lower()
        protocol_penalty += _PROTOCOL_SEVERITY_WEIGHTS.get(severity, 0.8)
    penalty += min(3.0, protocol_penalty)

    score = min(10.0, max_cvss + penalty)
    return round(score, 2)


def _derive_risk_factors(
    matches: List[Dict], flags: Dict, crypto_findings: List[Dict], protocol_findings: List[Dict], access_reasons: List[str]
) -> List[str]:
    factors = []
    for m in matches:
        cve = m.get("cve")
        cvss = m.get("cvss")
        if cve:
            factors.append(f"{cve} (CVSS {cvss}) on port {m.get('port')}")
    for flag in sorted(flags.keys()):
        factors.append(flag.replace("_", " "))
    for finding in crypto_findings:
        factors.append(
            f"{finding.get('type', 'crypto').upper()}:{finding.get('issue')} (port {finding.get('port')})"
        )
    for finding in protocol_findings:
        factors.append(
            f"PROTOCOL:{finding.get('issue')} (port {finding.get('port')})"
        )
    factors.extend(access_reasons)
    return factors


def assess_device(device: Dict, vuln_db: List[Dict], access_flags: Dict = None, access_reasons: List[str] = None) -> Dict:
    if access_flags is None:
        access_flags = {}
    if access_reasons is None:
        access_reasons = []

    services = device.get("services", [])
    matches = match_vulns(services, vuln_db)
    flags = dict(access_flags)
    crypto_findings = device.get("crypto_findings", [])
    protocol_findings = device.get("protocol_findings", [])

    for s in services:
        if s.get("port") == 23 and s.get("state") == "open":
            flags["telnet_open"] = True
        if s.get("port") in (80, 443) and ("admin" in (s.get("version") or "").lower()):
            flags["default_creds"] = True
    if crypto_findings:
        flags["weak_encryption"] = True

    score = compute_risk(matches, flags, crypto_findings, protocol_findings)
    risk_factors = _derive_risk_factors(matches, flags, crypto_findings, protocol_findings, access_reasons)
    return {
        "ip": device.get("ip"),
        "mac": _normalize_mac(device.get("mac", "")),
        "vendor": device.get("vendor"),
        "matches": matches,
        "crypto_findings": crypto_findings,
        "protocol_findings": protocol_findings,
        "risk_score": score,
        "flags": flags,
        "risk_factors": risk_factors,
    }


def assess_all(
    devices: List[Dict],
    vuln_db_path: str = VULN_DB_PATH,
    baseline_path: str = "",
    sightings_path: str = DEFAULT_SIGHTINGS_PATH,
) -> List[Dict]:
    db = load_vuln_db(vuln_db_path)
    baseline = load_baseline(baseline_path)
    sightings = load_sightings(sightings_path) if sightings_path else {"devices": {}}

    results = []
    for d in devices:
        first_seen = False
        if sightings_path:
            first_seen, _ = update_sighting(d, sightings)
        access_flags, access_reasons = evaluate_access_flags(d, baseline, first_seen)
        results.append(assess_device(d, db, access_flags, access_reasons))

    if sightings_path:
        save_sightings(sightings, sightings_path)
    return results


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("infile", help="discovery JSON file")
    p.add_argument("--out", default="iot_scan_assessment.json")
    p.add_argument("--vuln-db", default=VULN_DB_PATH)
    p.add_argument(
        "--baseline",
        default="",
        help="optional allowlist JSON to detect unauthorized devices",
    )
    p.add_argument(
        "--sightings",
        default=DEFAULT_SIGHTINGS_PATH,
        help="local sightings DB for first-seen detection; pass '' to disable",
    )
    args = p.parse_args()
    with open(args.infile) as f:
        data = json.load(f)
    devices = data.get("devices", [])
    res = assess_all(
        devices,
        vuln_db_path=args.vuln_db,
        baseline_path=args.baseline,
        sightings_path=args.sightings,
    )
    with open(args.out, "w") as f:
        json.dump({"assessment": res}, f, indent=2)
