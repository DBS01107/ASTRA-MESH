# ASTRA - AI-Powered Vulnerability Orchestrator + IoT Scanner

**ASTRA** is an adaptive security platform with two tracks:
- **Web/Infra Orchestrator**: AI-assisted, multi-tool vulnerability orchestration with live dashboarding.
- **IoT Scanner (local-first)**: lightweight LAN discovery for common IoT devices, weak-encryption checks, unauthorized-device detection, CVSS-based risk scoring, and one-click isolation scripts.

---



---

It features a futuristic, real-time **Next.js** dashboard and supports two distinct scanning modes:

- **Dynamic Mode**: Leverages an AI Planning Agent to analyze findings and intelligently decide which tools to run next. It adapts its attack strategy in real-time based on discovered assets and vulnerabilities.
- **Static Mode**: Executes a predictable, user-defined sequence of security tools.

---

## 🛰️ IoT Hackathon Mode (Local-Only)

The repository now also includes `iot_scanner/`, a privacy-focused scanner for home/small-office IoT networks.

- **Network Discovery + JSON Output**: Nmap-based host/service discovery with local JSON reports.
- **Weak Encryption Detection**: TLS/SSH checks via `ssl-enum-ciphers` and `ssh2-enum-algos`.
- **Unauthorized Access Detection**: optional baseline allowlist (`IP/MAC`) + first-seen tracking.
- **Risk Prioritization**: CVSS-informed scoring with risk factors and heatmap generation.
- **One-click Mitigation**: `iptables` quarantine script generation with whitelist and rollback script.
- **Scalability Goal**: configurable thread pool (`--max-workers`) for 50+ device environments.

### IoT Quickstart

```bash
# 1) Discovery (local network)
python -m iot_scanner.scanner 192.168.1.0/24 --out discovery.json --max-workers 25

# 2) Assessment (with optional allowlist)
python -m iot_scanner.assess discovery.json --out assessment.json \
  --baseline baseline_allowlist.json \
  --sightings iot_scanner/device_sightings.json

# 3) Heatmap/report (Python snippet or integrate in your pipeline)
# 4) Mitigation
python -m iot_scanner.mitigate assessment.json --threshold 7.0 \
  --out iot_mitigate.sh \
  --rollback-out iot_mitigate_rollback.sh \
  --whitelist-ip 192.168.1.1
```

For full IoT usage details, see `iot_scanner/README.md`.

---


## 🚀 Key Features

### 🧠 Reasoning Engine & AI Planning
- **Incremental Reasoning**: The AI engine analyzes findings *as they arrive* (Real-time), ensuring the dashboard reflects the current security posture instantly.
- **Adaptive Strategy**: Intelligently chains tools based on open ports, identified services, and discovered vulnerabilities.
- **Strategic Insight**: The "Reasoning Engine" panel displays the AI's high-level thoughts, explaining *why* it chose a specific path.
- **Exploit Intelligence Enrichment**: `searchsploit` checks detected technologies/services and feeds exploit references directly into AI planning context.

### 🕸️ Interactive Attack Graph
- **Visual Attack Paths**: Visualizes assets and findings as a dynamic node graph using ReactFlow.
- **Path Analysis**: Automatically traces potential compromise paths from entry points to critical assets.

### 📺 Live Next.js Dashboard
- **Real-time Log Streaming**: Monitor the scan's progress live via Server-Sent Events (SSE).
- **Custom Scanner Selection**: granular control over which tools to run (e.g., specific combinations of `nmap`, `nuclei`, etc.).
- **Live Discovery**: Findings populate the graph and log window instantly.
- **Checklist Coverage Tracking**: Coverage matrix for General/Passive/Active web checks is shown in the UI and reflected in reports.

### 🔐 Authentication & Persistence
- **Login + Registration**: Built-in user authentication for dashboard/API access.
- **Per-User Session Ownership**: Session IDs are mapped to specific users to prevent cross-user access.
- **Persistent Scan Records**: Findings, logs, reasoning, and SearchSploit matches are stored per user/session in the database.

### 📄 Reporting
- **Checklist Coverage in PDF**: Reports include total/detected/covered/uncovered counts and group-wise coverage.
- **SearchSploit Evidence in PDF**: ExploitDB matches are included in the report when exploit references are found.
- **AI-Visible Exploit Context**: SearchSploit results are injected into AI reasoning prompts for better recommendations.
- **NVD Zero-Day Intelligence**: Recent CVEs from the National Vulnerability Database are included in reports and AI context.
- **Unverified External Web Intel**: Early-stage threat signals from GitHub Security Advisories are included in a clearly labelled, disclaimer-gated section of the PDF and AI context.

### ⚡ Concurrent & Modular
- **Concurrent Execution**: Runs multiple tools in parallel for faster and more efficient scanning.
- **Modular Architecture**: Easily extendable with new tools, parsers, and rules.

---

## 🔬 How Dynamic Mode Works

1.  **Initial Scan**: ASTRA begins with a set of baseline enumeration tools (e.g., `nmap`, `whatweb`, `nuclei`).
2.  **Incremental Parsing**: As tools finish, their output is immediately parsed and added to the centralized Graph.
3.  **Automatic SearchSploit Pass**: If technology-revealing scanners are selected, ASTRA auto-runs `searchsploit` against detected technologies/services.
4.  **AI Analysis**: The Google ADK Agent analyzes the new findings plus SearchSploit exploit context.
5.  **Strategic Loop**: 
    -   The agent updates the "Reasoning Engine" display.
    -   It recommends new, targeted scans (e.g., "Found port 80, run `nikto`").
6.  **Execution**: The orchestrator executes the recommended tools automatically.
7.  **Visualization**: The Attack Graph updates in real-time to show the growing network of assets and vulnerabilities.

---

## Directory Structure

```
├── orchestrator
│   ├── core
│   │   ├── engine.py       # Core logic for static/dynamic scanning
│   │   ├── graph.py        # Graph database interface (NetworkX/Neo4j)
│   │   ├── parsers.py      # Tool output parsers
│   │   └── registry.py     # Tool definitions and commands
│   ├── server.py           # FastAPI Backend
│   └── main.py             # CLI Entrypoint
├── frontend                # Next.js Application
│   ├── src
│   │   ├── components      # React Components (Sidebar, ExplainPanel, etc.)
│   │   └── app             # Next.js Pages
├── google_adk              # AI Integration
│   ├── agent.py            # Gemini Agent Logic
│   └── tools.py            # Agent Tool Definitions
├── iot_scanner             # Lightweight IoT discovery/assessment/mitigation module
│   ├── scanner.py          # LAN discovery + service + crypto checks
│   ├── assess.py           # CVSS + unauthorized/new-device risk scoring
│   ├── mitigate.py         # Firewall isolation + rollback script generator
│   └── report.py           # JSON report writer + heatmap plotting
├── scripts
│   └── setup_venv.sh       # helper to create venv and install scanner deps
└── output                  # Raw Scan Results
```

---

## 🛠️ Tech Stack

-   **Backend**: Python 3.10+ (FastAPI, NetworkX, Google Generative AI)
-   **Frontend**: Next.js 14, React, TailwindCSS, ReactFlow
-   **AI**: Google Gemini 1.5 Flash (via Google ADK)
-   **Graph**: NetworkX (In-memory) / Neo4j (Optional persistence)
-   **IoT Local Scanner**: Python + Nmap + Matplotlib (`iot_scanner/`)

---

## 🔌 IoT-Only Setup (No Cloud Dependencies)

If you only want the local IoT scanner workflow (no dashboard, no AI, no cloud APIs):

```bash
./scripts/setup_venv.sh
source .venv/bin/activate

python -m iot_scanner.scanner 192.168.1.0/24 --out discovery.json
python -m iot_scanner.assess discovery.json --out assessment.json
python -m iot_scanner.mitigate assessment.json --out iot_mitigate.sh
```

This mode runs fully local by default.

---

##  Getting Started (Recommended: Docker)

The easiest way to run ASTRA is with Docker, which automatically installs all security tools and dependencies.
This includes `searchsploit` (via the `exploitdb` package) for exploit reference enrichment.

### 1. Prerequisites
-   **Docker** & **Docker Compose**
-   **Google Gemini API Key**: Get it from [Google AI Studio](https://aistudio.google.com/app/apikey).

### 2. Quick Start
1.  Clone the repo:
    ```bash
    git clone https://github.com/DBS01107/ASTRA.git
    cd ASTRA
    ```
2.  Configure environment variables:
    ```bash
    # Copy the example and edit with your keys
    cp .env.example .env
    ```
    
    **Required:**
    - `GOOGLE_API_KEY` - Your Google Gemini API key ([Get it here](https://aistudio.google.com/app/apikey))
    
    **Optional:**
    - `ASTRA_JWT_SECRET` - Secret used to sign authentication tokens.
    - `ASTRA_JWT_EXPIRE_HOURS` - Token expiry window (default: `24`).
    - `ASTRA_DATABASE_URL` - SQLAlchemy connection URL for user/session persistence (default: `sqlite:///orchestrator/output/astra.db`).
    - `NVD_API_KEY` - For enhanced CVE data ([Get it here](https://nvd.nist.gov/developers/request-an-api-key))
    - `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` - For persistent graph storage (defaults to in-memory)
3.  Run with Docker:
    ```bash
    sudo docker compose up --build
    ```

That's it! Access the dashboard at **http://localhost:3000**.
Create an account from the login screen, then run scans. Scan history is stored per user.

---

## ⚙️ Manual Installation (Advanced)

If you prefer to run locally without Docker (e.g., on Kali Linux natively):

### 1. Install Tools
```bash
sudo apt update && sudo apt install -y nmap whatweb nuclei nikto wpscan joomscan enum4linux sqlmap exploitdb
```

`exploitdb` provides the `searchsploit` binary used for automatic exploit reference enrichment.

### 2. Backend Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Frontend Setup
```bash
cd frontend
npm install
```

### 4. Run
**Terminal 1 (Backend):**
```bash
source .venv/bin/activate
PYTHONPATH=. python orchestrator/server.py
```

**Terminal 2 (Frontend):**
```bash
cd frontend
npm run dev
```

---

## SearchSploit Auto-Selection Behavior

- If a technology-revealing scanner is selected (`nmap`, `whatweb`, `nuclei`, `nikto`, etc.), ASTRA automatically enables `searchsploit`.
- `searchsploit` runs as an internal enrichment scanner and queries ExploitDB for technologies/services detected across findings from all tools.
- Exploit matches are added to AI reasoning context.
- Exploit matches are persisted for session reporting.
- Exploit matches are included in PDF reports when matches are found.

---

## 🌐 Threat Intelligence Sources & API Setup

ASTRA enriches scan results with threat intelligence from multiple sources. Each source below has its own setup steps.

---

### 1. NVD (National Vulnerability Database) — *Optional, Recommended*

Used for: Recent CVE lookups against detected technologies. Works without a key but is rate-limited.

- Unauthenticated: 5 requests / 30 seconds
- Authenticated: 50 requests / 30 seconds

**Steps:**
1. Go to [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
2. Fill in your name and email address, then submit.
3. Check your email — NVD will send your API key within a few minutes.
4. Add it to your `.env`:
   ```
   NVD_API_KEY=your_nvd_api_key_here
   ```

---

### 2. GitHub Security Advisories — *Optional, Recommended*

Used for: Querying the GitHub Advisory Database for vulnerabilities related to detected technologies. This API is **free and works without a token**, but adding a token raises the rate limit from 60 to 5,000 requests/hour. Results appear faster than NVD (often 1-2 weeks ahead).

**Steps to get a GitHub token (optional but recommended):**
1. Log in to [https://github.com](https://github.com).
2. Go to **Settings → Developer settings → Personal access tokens → Tokens (classic)**.
   - Direct link: [https://github.com/settings/tokens](https://github.com/settings/tokens)
3. Click **Generate new token (classic)**.
4. Give it a name (e.g., `ASTRA-intel`).
5. Under **Select scopes**, you do **not** need to check anything — a token with no scopes is sufficient for public advisory access.
6. Click **Generate token** and copy it immediately (it won't be shown again).
7. Add it to your `.env`:
   ```
   GITHUB_TOKEN=ghp_your_token_here
   ```

> If `GITHUB_TOKEN` is not set, ASTRA will still query GitHub Advisories anonymously.

---

### Summary of All Environment Variables

| Variable | Required | Source | Purpose |
|---|---|---|---|
| `GOOGLE_API_KEY` | ✅ Yes | [Google AI Studio](https://aistudio.google.com/app/apikey) | Gemini AI agent |
| `ASTRA_JWT_SECRET` | ✅ Yes | Generate locally | Signs login tokens |
| `NVD_API_KEY` | Optional | [NVD](https://nvd.nist.gov/developers/request-an-api-key) | Higher CVE API rate limits |
| `GITHUB_TOKEN` | Optional | [GitHub Settings](https://github.com/settings/tokens) | Higher advisory API rate limits |
| `ASTRA_JWT_EXPIRE_HOURS` | Optional | — | Token lifetime (default: 24h) |
| `ASTRA_DATABASE_URL` | Optional | — | DB connection (default: SQLite) |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` | Optional | Self-hosted | Persistent graph storage |

For **IoT-only mode** (`iot_scanner/`), no API keys are required.

---

### ⚠️ Disclaimer on Unverified Web Intel

Results from **GitHub Security Advisories** are collected from the open web and have **not been verified by NVD or ExploitDB**. They may contain:
- False positives
- Misattributed CVE references
- Inaccurate severity scores
- Outdated or retracted information

These results are clearly labelled in both the PDF report (purple-header table with disclaimer) and the AI chat context (`[UNVERIFIED EXTERNAL WEB INTEL]` block). Treat them as **leads for further investigation only**, not confirmed vulnerabilities.



## Creators

### Devang Sonawane (https://github.com/DBS01107) (https://linkedin.com/in/devang-sonawane-73925a1b4/)
### Sarthak Pujari  (https://github.com/Sarthakzzzzz) (https://linkedin.com/in/sarthakzzzzz/)
### Adwait Bangale  (https://github.com/toxicated53) (https://www.linkedin.com/in/adwait-bangale-330710288/)

---

#### Original team
- Devang Sonawane
- Sarthak Pujari
- Adwait Bangale
- Rashi Singh
- Ved Asawa
- Aditi Kharpade
