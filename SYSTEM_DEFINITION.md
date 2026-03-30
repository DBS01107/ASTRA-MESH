# ASTRA — System Definition

## Overview

ASTRA is a dual-track security platform:

1. **Web/Infra Orchestrator**: an AI-powered vulnerability orchestration system that coordinates multiple scanners, ingests findings into a graph, and drives adaptive scan planning through an AI agent.
2. **IoT Local Scanner**: a lightweight, privacy-focused LAN scanner for common IoT devices that performs discovery, weak-encryption checks, unauthorized-device detection, CVSS-informed prioritization, and mitigation script generation.

The web/infra track provides a live Next.js dashboard for real-time monitoring/reporting, while the IoT track is CLI-first and local-only by default.

## High-level Components

- **Orchestrator (Backend)**: FastAPI-based backend that runs scans, parses outputs, maintains an in-memory or persistent graph, and exposes APIs and SSE for the frontend. Core implementation lives in [orchestrator](orchestrator).
  - Key files:
    - [orchestrator/server.py](orchestrator/server.py) — API server entrypoint.
    - [orchestrator/main.py](orchestrator/main.py) — CLI entrypoint for running orchestrator tools/scans.
    - [orchestrator/core/engine.py](orchestrator/core/engine.py) — core scanning logic for static/dynamic modes.
    - [orchestrator/core/graph.py](orchestrator/core/graph.py) — graph interface (NetworkX / optional Neo4j persistence).
    - [orchestrator/core/parsers.py](orchestrator/core/parsers.py) — tool output parsers.
    - [orchestrator/core/registry.py](orchestrator/core/registry.py) — scanner definitions and commands.

- **AI Agent (Google ADK integration)**: Integrates Gemini (Google ADK) to reason about findings and plan next steps.
  - Key files: [google_adk/agent.py](google_adk/agent.py), [google_adk/tools.py](google_adk/tools.py), [google_adk/rag_engine.py](google_adk/rag_engine.py).

- **Frontend (Next.js)**: Real-time dashboard, attack graph, and interactive controls that connect to the backend via REST and Server-Sent Events.
  - Key paths:
    - [frontend/src/app](frontend/src/app) — top-level Next.js app pages.
    - [frontend/src/components](frontend/src/components) — React components (AttackGraph, AIChat, auth panels).
    - [frontend/README.md](frontend/README.md) — frontend-specific notes.

- **IoT Scanner (`iot_scanner/`)**: Local CLI workflow for LAN discovery and mitigation planning.
  - Key files:
    - [iot_scanner/scanner.py](iot_scanner/scanner.py) — Nmap-based host/service discovery + TLS/SSH weak-encryption checks.
    - [iot_scanner/assess.py](iot_scanner/assess.py) — CVE/CVSS matching, baseline allowlist checks, first-seen tracking, risk scoring.
    - [iot_scanner/report.py](iot_scanner/report.py) — JSON report writer + heatmap generation.
    - [iot_scanner/mitigate.py](iot_scanner/mitigate.py) — one-click firewall quarantine/rollback script generation.
    - [iot_scanner/vuln_db.json](iot_scanner/vuln_db.json) — local vulnerability signature database.

- **Output / Persistence**: Raw scanner outputs live under `output/raw`. Optional SQLite DB for sessions is created under `orchestrator/output/astra.db` by default.

## Data Flow

### Web/Infra Orchestrator Flow

1. User initiates a scan (via dashboard or CLI).
2. Orchestrator launches configured scanners (e.g., `nmap`, `nuclei`, `nikto`) using commands defined in the registry.
3. Scanner outputs are parsed by parsers in real-time and ingested into the Graph (`orchestrator/core/parsers.py` → `orchestrator/core/graph.py`).
4. Parsed findings are persisted (in-memory NetworkX or Neo4j if configured) and stored in `output/`.
5. The Google ADK Agent enriches findings with SearchSploit/ExploitDB and NVD/GitHub advisory context, then reasons and recommends follow-up scans.
6. The planner (`orchestrator/core/planner.py`) schedules follow-up tools; the engine executes them, closing the loop.
7. Frontend receives live updates via SSE and displays the Attack Graph and AI reasoning.

### IoT Scanner Flow (Local-only)

1. User runs subnet discovery (`python -m iot_scanner.scanner <subnet>`).
2. Scanner performs host discovery, service/version scanning, and optional TLS/SSH weakness checks.
3. Discovery output is written as JSON (`devices`, metadata, and crypto findings).
4. User runs assessment (`python -m iot_scanner.assess discovery.json ...`).
5. Assessment matches services against local `vuln_db.json`, applies CVSS-informed scoring, and flags:
   - weak encryption
   - new/first-seen devices
   - unauthorized devices (if baseline allowlist is provided)
6. User generates heatmap/report and optional mitigation scripts:
   - risk heatmap (`iot_scanner/report.py`)
   - quarantine + rollback firewall scripts (`iot_scanner/mitigate.py`)

## Key Files & Modules

- Repository root: `README.md`, `docker-compose.yml`, `requirements.txt`.
- Backend API: [orchestrator/server.py](orchestrator/server.py).
- Core logic: [orchestrator/core/engine.py](orchestrator/core/engine.py), [orchestrator/core/planner.py](orchestrator/core/planner.py), [orchestrator/core/runner.py](orchestrator/core/runner.py).
- Parsers & extractors: [orchestrator/core/parsers.py](orchestrator/core/parsers.py), [orchestrator/core/extractors](orchestrator/core/extractors).
- Rules & detection: [orchestrator/rules](orchestrator/rules) and [orchestrator/core/rules_loader.py](orchestrator/core/rules_loader.py).
- AI integration: [google_adk/agent.py](google_adk/agent.py), [google_adk/tools.py](google_adk/tools.py).
- Frontend UI: [frontend/src/components](frontend/src/components) and [frontend/src/app](frontend/src/app).
- IoT module: [iot_scanner/scanner.py](iot_scanner/scanner.py), [iot_scanner/assess.py](iot_scanner/assess.py), [iot_scanner/report.py](iot_scanner/report.py), [iot_scanner/mitigate.py](iot_scanner/mitigate.py).

## Environment Variables (important)

Required / recommended variables (also listed in `README.md`):

- `GOOGLE_API_KEY` — Gemini API key (required for AI agent).
- `ASTRA_JWT_SECRET` — JWT signing secret.
- `ASTRA_DATABASE_URL` — SQLAlchemy DB URL (defaults to SQLite under `orchestrator/output/astra.db`).
- `NVD_API_KEY` — optional NVD API key for CVE lookups.
- `GITHUB_TOKEN` — optional GitHub token for advisory queries.
- `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` — optional Neo4j config for persistent graph storage.

IoT scanner mode does not require cloud/API credentials by default.

## Deployment & Run Modes

- Docker Compose (recommended): `docker-compose.yml` at repo root configures backend + frontend and required tools.
- Local (advanced): create a Python venv and run `pip install -r requirements.txt`, then run the backend with `PYTHONPATH=. python orchestrator/server.py` and the frontend with `npm run dev` from `frontend/`.
- IoT-only local mode: run `./scripts/setup_venv.sh`, then execute modules under `iot_scanner/` (`scanner`, `assess`, `report`, `mitigate`) directly from CLI.

## Scanning Modes

- **Dynamic Mode**: AI-driven planning — agent incrementally recommends next scanners.
- **Static Mode**: Predefined sequence of tools executed deterministically.
- **IoT Local Mode**: CLI-first workflow for LAN IoT discovery, risk scoring, and mitigation script generation without cloud dependencies.

## Extensibility

- Add new scanner definitions in `orchestrator/core/registry.py` and parsers in `orchestrator/core/parsers.py` or `orchestrator/core/extractors/`.
- Enrichment sources (SearchSploit, NVD, GitHub) are integrated via modules in `google_adk` and `orchestrator/core/dependencies.py`.
- Extend IoT detections by updating `iot_scanner/vuln_db.json`, weak-crypto markers in `iot_scanner/scanner.py`, and custom risk logic in `iot_scanner/assess.py`.

## Testing & Verification

- Tests and verification scripts exist under `tests/` and `verification/`. Examples:
  - `tests/test_adk_agent.py` — AI agent tests.
  - `verification/verify_complete_flow.py` — end-to-end verification harness.
- IoT workflow can be validated by running `iot_scanner` modules sequentially (`scanner` → `assess` → `report/mitigate`) against a controlled subnet or prepared JSON fixtures.

## Security Considerations

- The system runs external scanners and may execute arbitrary binaries; run in an isolated environment (containers) and restrict network access appropriately.
- Secure `ASTRA_JWT_SECRET` and API keys; do not commit secrets.
- IoT scans may require elevated Nmap capabilities depending on scan type/environment; run only on authorized networks.
- Mitigation scripts modify local firewall rules; always keep whitelist entries for trusted gateway/admin hosts and keep rollback scripts accessible.

## Quick Start (summary)

1. Copy `.env` (from `.env.example` if present) and set `GOOGLE_API_KEY` and `ASTRA_JWT_SECRET`.
2. Recommended: `sudo docker compose up --build`.
3. Or locally: `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt` then run backend and frontend separately.
4. IoT-only path: `./scripts/setup_venv.sh` then run `python -m iot_scanner.scanner`, `python -m iot_scanner.assess`, and `python -m iot_scanner.mitigate`.

---

This file is a concise system definition to help contributors and maintainers understand architecture, data flow, and where to extend or operate the system.
