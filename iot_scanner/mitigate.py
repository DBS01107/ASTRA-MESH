import argparse
import ipaddress
import json
import os
from typing import Dict, List

FIREWALL_SCRIPT = "iot_mitigate.sh"
DEFAULT_CHAIN = "ASTRA_IOT_QUARANTINE"


def _is_valid_ip_or_cidr(value: str) -> bool:
    if not value:
        return False
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _dedupe_and_validate_ips(values: List[str]) -> List[str]:
    out = []
    seen = set()
    for raw in values:
        value = (raw or "").strip()
        if not value:
            continue
        if value in seen:
            continue
        if not _is_valid_ip_or_cidr(value):
            continue
        seen.add(value)
        out.append(value)
    return out


def load_whitelist_file(path: str = "") -> List[str]:
    if not path:
        return []
    with open(path, "r") as f:
        lines = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]
    return _dedupe_and_validate_ips(lines)


def generate_firewall_script(
    block_ips: List[str],
    outpath: str = FIREWALL_SCRIPT,
    whitelist_ips: List[str] = None,
    rollback_out: str = "",
    chain_name: str = DEFAULT_CHAIN,
) -> Dict:
    whitelist = _dedupe_and_validate_ips(whitelist_ips or [])
    whitelist_set = set(whitelist)
    block = [ip for ip in _dedupe_and_validate_ips(block_ips) if ip not in whitelist_set]

    if not rollback_out:
        rollback_out = f"{outpath}.rollback.sh"

    lines = [
        "#!/bin/sh",
        "set -eu",
        f'CHAIN="{chain_name}"',
        f'ROLLBACK_SCRIPT="{rollback_out}"',
        "",
        "if ! command -v iptables >/dev/null 2>&1; then",
        '  echo "iptables not found in PATH"',
        "  exit 1",
        "fi",
        "",
        "# Create/refresh dedicated quarantine chain",
        'iptables -N "$CHAIN" 2>/dev/null || true',
        'iptables -F "$CHAIN"',
        "",
        "# Whitelist first to avoid accidental lockouts",
    ]
    for ip in whitelist:
        lines.append(f'iptables -A "$CHAIN" -s {ip} -j RETURN')

    lines.extend(["", "# Drop blocked IoT devices"])
    for ip in block:
        lines.append(f'iptables -A "$CHAIN" -s {ip} -j DROP')

    lines.extend(
        [
            "",
            "# Hook chain once (idempotent)",
            'iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN"',
            'iptables -C FORWARD -j "$CHAIN" 2>/dev/null || iptables -I FORWARD 1 -j "$CHAIN"',
            "",
            'echo "Applied IoT quarantine chain: $CHAIN"',
            f'echo "Blocked: {len(block)} device(s), Whitelisted: {len(whitelist)} entry(ies)"',
            'echo "Rollback: $ROLLBACK_SCRIPT"',
        ]
    )

    rollback_lines = [
        "#!/bin/sh",
        "set -eu",
        f'CHAIN="{chain_name}"',
        'iptables -D INPUT -j "$CHAIN" 2>/dev/null || true',
        'iptables -D FORWARD -j "$CHAIN" 2>/dev/null || true',
        'iptables -F "$CHAIN" 2>/dev/null || true',
        'iptables -X "$CHAIN" 2>/dev/null || true',
        'echo "Rollback complete for chain: $CHAIN"',
    ]

    with open(outpath, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(outpath, 0o755)

    with open(rollback_out, "w") as f:
        f.write("\n".join(rollback_lines) + "\n")
    os.chmod(rollback_out, 0o755)

    return {
        "script_path": outpath,
        "rollback_path": rollback_out,
        "blocked_ips": block,
        "whitelist_ips": whitelist,
    }


def suggest_mitigation(assessment: List[Dict], threshold: float = 7.0) -> List[str]:
    to_block = []
    for a in assessment:
        ip = a.get("ip")
        if not ip:
            continue
        if a.get("risk_score", 0.0) >= threshold:
            to_block.append(ip)
    return to_block


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("infile")
    p.add_argument("--threshold", type=float, default=7.0)
    p.add_argument("--out", default=FIREWALL_SCRIPT)
    p.add_argument("--rollback-out", default="")
    p.add_argument("--chain", default=DEFAULT_CHAIN)
    p.add_argument("--whitelist-file", default="", help="newline-separated IP/CIDR list")
    p.add_argument(
        "--whitelist-ip",
        action="append",
        default=[],
        help="can be passed multiple times",
    )
    args = p.parse_args()

    with open(args.infile) as f:
        data = json.load(f)
    assessment = data.get("assessment", [])
    block = suggest_mitigation(assessment, args.threshold)

    whitelist = list(args.whitelist_ip)
    whitelist.extend(load_whitelist_file(args.whitelist_file))
    generated = generate_firewall_script(
        block,
        outpath=args.out,
        whitelist_ips=whitelist,
        rollback_out=args.rollback_out,
        chain_name=args.chain,
    )
    print("Wrote", generated["script_path"])
    print("Rollback", generated["rollback_path"])
    print("Blocked", len(generated["blocked_ips"]), "devices")
