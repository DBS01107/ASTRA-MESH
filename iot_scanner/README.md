# Lightweight IoT Scanner

This package provides a small, privacy-focused, local IoT discovery and vulnerability workflow targeting home/small-office networks and devices (smart bulbs, cameras, routers).

Quick features
- Network discovery using Nmap (local-only)
- **Advanced IoT Protocol Scanning:** Modular unauthenticated access detection for **MQTT**, **RTSP**, and **CoAP** (including extended ports and UDP).
- **Offline Device Fingerprinting:** Uses a lightweight local `.py` MAC dictionary for fast vendor identification (Espressif, Tuya, Philips, etc.).
- Service/version matching against a local `vuln_db.json`
- Weak encryption checks (TLS/SSH) using Nmap scripts (`ssl-enum-ciphers`, `ssh2-enum-algos`)
- Unauthorized device detection using an optional local baseline allowlist
- First-seen device tracking via a local sightings database
- Risk scoring (CVSS-informed) and highly readable visual **HTML reporting** and heatmap visualization
- One-click mitigation script generator with rollback support (iptables), suitable for Raspberry Pi

Prerequisites
- `nmap` binary installed and executable in PATH
- Python 3.10+
- Install Python deps: `pip install -r requirements.txt` (may install `matplotlib` for reports)

Virtual environment (recommended)

Use the included helper to create a local venv and install scanner deps:

```bash
./scripts/setup_venv.sh       # minimal deps (matplotlib, python-nmap, numpy)
source .venv/bin/activate
# or for full project deps:
./scripts/setup_venv.sh all
```

Usage

- Discover hosts on subnet and save JSON:

```bash
python -m iot_scanner.scanner 192.168.1.0/24 --out discovery.json --max-workers 25
```

- Assess discovered hosts against local vuln DB + baseline allowlist:

```bash
python -m iot_scanner.assess discovery.json --out assessment.json \
  --baseline baseline_allowlist.json \
  --sightings iot_scanner/device_sightings.json
```

- Generate assessment JSON, Heatmap (PNG), and human-readable HTML Report:

```bash
python -m iot_scanner.report assessment.json --out-html iot_report.html
```

- One-click firewall isolation script for high-risk devices (Raspberry Pi):

```bash
python -m iot_scanner.mitigate assessment.json --threshold 7.0 \
  --out iot_mitigate.sh \
  --rollback-out iot_mitigate_rollback.sh \
  --whitelist-ip 192.168.1.1 \
  --whitelist-ip 192.168.1.2
sudo ./iot_mitigate.sh
# rollback if needed:
sudo ./iot_mitigate_rollback.sh
```

Baseline allowlist example (`baseline_allowlist.json`)

```json
{
  "allowed_ips": ["192.168.1.10", "192.168.1.20"],
  "allowed_macs": ["aa:bb:cc:dd:ee:ff"],
  "allowed_devices": [
    { "ip": "192.168.1.30", "mac": "11:22:33:44:55:66" }
  ]
}
```

Notes on outputs
- **Discovery** output now includes host identity metadata (`ip`, `name`, `mac`, `vendor`). Missing vendors are intelligently inferred via a local OUI dictionary.
- **Protocol Findings** check for granular IoT vulnerabilities (e.g., `anonymous_subscribe` for MQTT).
- **Assessment** output assigns high CVSS penalties for open/insecure IoT protocols and flags unauthorized devices.
- Mitigation command writes two scripts: the apply script and rollback script.

Privacy & Scalability
- All processing and matching are local; no cloud uploads by default.
- Designed to handle 50+ devices: scanning uses a thread pool (adjust `max_workers`), and reports are generated locally.

Extending
- Add entries to `vuln_db.json` to improve detection (service, version_regex, CVE, CVSS).
- Add or tune weak-crypto markers in `scanner.py` for stricter TLS/SSH policy.
- Replace iptables script generator with `nftables` or platform-specific firewall as needed.

Notes
- This tool relies on Nmap for accurate network/service discovery; keep Nmap up-to-date.
- Use responsibly on networks you own or have permission to scan.
