import asyncio
import os
import sys
from queue import Empty
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# Load .env when running directly (safe no-op when env vars are already injected).
load_dotenv()

# Add the ASTRA root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from google_adk.agent import ScanAgent
from orchestrator.core import dependencies, engine, persistence, state, utils
from orchestrator.core.checks_catalog import evaluate_check_coverage, get_checks_catalog
from orchestrator.core.db import (
    ScanSession,
    SessionLocal,
    SessionNotFoundError,
    SessionOwnershipError,
    User,
    create_user,
    ensure_scan_session_owner,
    get_user_by_email,
    get_user_by_id,
    get_user_by_username,
    init_db,
    json_loads_safe,
)
from orchestrator.core.security import (
    TokenValidationError,
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)

DEFAULT_DEV_CORS_ORIGIN_REGEX = (
    r"^https?://("
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|"
    r"[a-zA-Z0-9-]+\.local|"
    r"10(?:\.\d{1,3}){3}|"
    r"192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}"
    r")(?::\d+)?$"
)


def _parse_csv_env(name: str) -> List[str]:
    raw_value = os.getenv(name, "")
    return [entry.strip().rstrip("/") for entry in raw_value.split(",") if entry.strip()]


def _resolve_cors_origins() -> List[str]:
    configured_origins = _parse_csv_env("ASTRA_CORS_ORIGINS")
    if configured_origins:
        return configured_origins

    # Local-first defaults for common frontend dev ports.
    return [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://0.0.0.0:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://0.0.0.0:5173",
    ]


def _resolve_cors_origin_regex() -> Optional[str]:
    configured_regex = os.getenv("ASTRA_CORS_ORIGIN_REGEX", "").strip()
    if configured_regex:
        return configured_regex

    # If explicit origins are configured, do not add an implicit wildcard regex.
    if os.getenv("ASTRA_CORS_ORIGINS", "").strip():
        return None

    # Allow private-network and .local origins for laptop <-> LAN backend development.
    return DEFAULT_DEV_CORS_ORIGIN_REGEX


ALLOWED_CORS_ORIGINS = _resolve_cors_origins()
ALLOWED_CORS_ORIGIN_REGEX = _resolve_cors_origin_regex()

app = FastAPI(title="ASTRA API")
bearer_scheme = HTTPBearer(auto_error=False)


def _sanitize_session_id(raw_session_id: Optional[str]) -> str:
    if not raw_session_id:
        return "default"
    cleaned = raw_session_id.strip()
    if not cleaned:
        return "default"
    return cleaned[:128]


def _safe_filename_fragment(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value)


def _require_valid_credentials(username: str, password: str) -> None:
    if len(username.strip()) < 3:
        raise HTTPException(status_code=422, detail="Username must be at least 3 characters.")
    if len(password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")


def _serialize_user(user: User) -> Dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


def _serialize_scan_summary(scan: ScanSession) -> Dict[str, Any]:
    return {
        "session_id": scan.session_id,
        "target": scan.target,
        "mode": scan.mode,
        "scanners": scan.scanners,
        "status": scan.status,
        "error": scan.error,
        "started_at": scan.started_at,
        "ended_at": scan.ended_at,
        "finding_count": scan.finding_count,
        "updated_at": scan.updated_at.isoformat() if scan.updated_at else None,
    }


def _serialize_scan_snapshot(scan: ScanSession) -> Dict[str, Any]:
    return {
        "session_id": scan.session_id,
        "target": scan.target,
        "mode": scan.mode,
        "scanners": scan.scanners,
        "status": scan.status,
        "error": scan.error,
        "started_at": scan.started_at,
        "ended_at": scan.ended_at,
        "finding_count": scan.finding_count,
        "reasoning": scan.reasoning or "",
        "findings": json_loads_safe(scan.findings_json, []),
        "logs": json_loads_safe(scan.logs_json, []),
        "searchsploit_matches": json_loads_safe(scan.searchsploit_matches_json, []),
        "zeroday_matches": json_loads_safe(scan.zeroday_matches_json, []),
        "remediation": json_loads_safe(scan.remediation_json, {}),
    }


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    auth_token: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> User:
    token = auth_token
    if not token and credentials is not None:
        token = credentials.credentials

    if not token:
        raise HTTPException(status_code=401, detail="Authentication required.")

    try:
        payload = decode_access_token(token)
        user_id = int(payload.get("sub"))
    except (TokenValidationError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    user = get_user_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User is not active.")
    return user


def _assert_session_access(
    db: Session,
    user: User,
    session_id: str,
    create_if_missing: bool,
) -> ScanSession:
    try:
        return ensure_scan_session_owner(
            db,
            user_id=user.id,
            session_id=session_id,
            create_if_missing=create_if_missing,
        )
    except SessionOwnershipError:
        raise HTTPException(status_code=403, detail="Session belongs to another user.")
    except SessionNotFoundError:
        raise HTTPException(status_code=404, detail="Session not found.")


@app.on_event("startup")
async def startup_event() -> None:
    init_db()


# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_CORS_ORIGINS,
    allow_origin_regex=ALLOWED_CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=512)
    mode: str = Field(default="dynamic", pattern="^(dynamic|static)$")
    scanners: Optional[str] = Field(default="all", max_length=1024)
    session_id: Optional[str] = Field(default=None, max_length=128)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target must not be empty.")
        return v


class ChatRequest(BaseModel):
    logs: List[str] = Field(default_factory=list, max_length=200)
    question: str = Field(min_length=1, max_length=2000)
    session_id: Optional[str] = None

    @field_validator("logs")
    @classmethod
    def validate_logs(cls, v: List[str]) -> List[str]:
        return [entry[:2000] for entry in v if isinstance(entry, str)][:200]

    @field_validator("question")
    @classmethod
    def validate_question(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Question must not be empty.")
        return v


class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


# Initialize agent lazily or globally
ai_agent = ScanAgent()


@app.get("/")
async def root():
    return {"status": "ASTRA Core AI Online"}


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
async def register_user(request: RegisterRequest, db: Session = Depends(get_db)):
    _require_valid_credentials(request.username, request.password)

    if get_user_by_username(db, request.username):
        raise HTTPException(status_code=409, detail="Username already exists.")
    if request.email and get_user_by_email(db, request.email):
        raise HTTPException(status_code=409, detail="Email already exists.")

    password_hash = hash_password(request.password)
    try:
        user = create_user(db, username=request.username, password_hash=password_hash, email=request.email)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="User already exists.")

    token = create_access_token(user_id=user.id, username=user.username)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _serialize_user(user),
    }


@app.post("/api/auth/login")
async def login_user(request: LoginRequest, db: Session = Depends(get_db)):
    user = get_user_by_username(db, request.username)
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User is inactive.")

    token = create_access_token(user_id=user.id, username=user.username)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": _serialize_user(user),
    }


@app.get("/api/auth/me")
async def auth_me(current_user: User = Depends(get_current_user)):
    return {"user": _serialize_user(current_user)}


@app.get("/api/scans")
async def list_scans(
    limit: int = Query(default=25, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scans = persistence.list_user_scans(db, user_id=current_user.id, limit=limit)
    return {"scans": [_serialize_scan_summary(scan) for scan in scans]}


@app.get("/api/scans/{session_id}")
async def get_scan_snapshot(
    session_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    resolved_session_id = _sanitize_session_id(session_id)
    scan = _assert_session_access(db, current_user, resolved_session_id, create_if_missing=False)
    return _serialize_scan_snapshot(scan)


@app.get("/graph")
async def get_graph(
    session_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns the graph in a format compatible with ReactFlow (Bramhastra UI).
    """
    resolved_session_id = _sanitize_session_id(session_id)
    _assert_session_access(db, current_user, resolved_session_id, create_if_missing=True)

    session_graph = state.get_graph(resolved_session_id)

    nodes = []
    edges = []

    # Simple mapping of NetworkX nodes to ReactFlow nodes
    for node_id in session_graph.g.nodes:
        data = session_graph.g.nodes[node_id]
        node_type = data.get("type", "unknown")

        # Determine styling based on type
        bg_color = "#22d3ee"  # Default Cyan
        if node_type == "finding":
            bg_color = "#f59e0b"  # Orange
        if node_type == "impact":
            bg_color = "#ef4444"  # Red

        nodes.append(
            {
                "id": str(node_id),
                "type": node_type,
                "data": {
                    "label": data.get("label", node_id),
                    "severity": data.get("severity"),
                    "cvss": data.get("cvss") or data.get("cvss_score")
                }
            }
        )

    for source, target, _data in session_graph.g.edges(data=True):
        edges.append(
            {
                "id": f"e-{source}-{target}",
                "source": str(source),
                "target": str(target),
                "animated": True,
                "markerEnd": {"type": "arrowclosed", "color": "#22d3ee"},
                "style": {"stroke": "#22d3ee", "strokeWidth": 2},
            }
        )

    return {"nodes": nodes, "edges": edges}


def run_scan_in_background(
    target: str,
    mode: str,
    scanners: Optional[str],
    session_id: str,
    user_id: int,
):
    """
    Triggers the orchestrator engine and pushes logs to queue.
    """
    resolved_session_id = _sanitize_session_id(session_id)
    state.ensure_session(resolved_session_id)
    state.start_scan(target, mode, scanners, resolved_session_id)
    session_graph = state.get_graph(resolved_session_id)

    log_msg = f"[SERVER] Starting {mode} scan on {target}...\n"
    print(log_msg, end="")
    state.push_log(log_msg, resolved_session_id)
    persistence.sync_scan_session_from_state(
        user_id=user_id,
        session_id=resolved_session_id,
        status_override="running",
        error_override=None,
    )

    try:
        for line in engine.run_orchestrator(
            primary_target=target,
            enable_arg=scanners or "all",
            concurrency=5,
            mode=mode,
            dry_run=False,
            graph=session_graph,
            session_id=resolved_session_id,
        ):
            if isinstance(line, str):
                print(line, end="")
                state.push_log(line, resolved_session_id)
            if state.get_scan_metadata(resolved_session_id).get("status") == "stopped":
                state.push_log("[SERVER] Scan stopped by user.\n", resolved_session_id)
                break
        status_val = state.get_scan_metadata(resolved_session_id).get("status", "")
        if status_val != "stopped":
            state.finish_scan(resolved_session_id, status="completed")
            completed = "[SERVER] Scan completed successfully.\n"
        else:
            completed = "[SERVER] Scan stopped.\n"
        print(completed, end="")
        state.push_log(completed, resolved_session_id)
        persistence.sync_scan_session_from_state(
            user_id=user_id,
            session_id=resolved_session_id,
            status_override=status_val if status_val == "stopped" else "completed",
            error_override=None,
        )
    except Exception as exc:
        failure = f"[SERVER] Scan failed: {exc}\n"
        print(failure, end="")
        state.push_log(failure, resolved_session_id)
        state.finish_scan(resolved_session_id, status="failed", error=str(exc))
        persistence.sync_scan_session_from_state(
            user_id=user_id,
            session_id=resolved_session_id,
            status_override="failed",
            error_override=str(exc),
        )


async def event_generator(session_id: str):
    """Generator for SSE to stream log messages."""
    session_queue = state.get_log_queue(session_id)
    completion_emitted = False
    while True:
        try:
            # Non-blocking get with timeout
            message = session_queue.get(timeout=1.0)
            yield f"data: {message}\n\n"
        except Empty:
            scan_metadata = state.get_scan_metadata(session_id)
            status_label = scan_metadata.get("status")
            if status_label == "running":
                completion_emitted = False
            elif status_label in {"completed", "failed"} and not completion_emitted and session_queue.empty():
                yield f"event: complete\ndata: {status_label}\n\n"
                completion_emitted = True
            # Send keepalive
            yield f": keepalive\n\n"
            await asyncio.sleep(0.5)


@app.get("/api/scan/stream")
async def stream_logs(
    session_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Server-Sent Events endpoint for streaming scan logs.
    """
    resolved_session_id = _sanitize_session_id(session_id)
    _assert_session_access(db, current_user, resolved_session_id, create_if_missing=True)

    state.ensure_session(resolved_session_id)
    return StreamingResponse(
        event_generator(resolved_session_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


@app.post("/api/scan")
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Initiates a security scan.
    """
    if not utils.is_valid_target(request.target):
        return {"error": "Invalid target format"}

    resolved_session_id = _sanitize_session_id(request.session_id)
    _assert_session_access(db, current_user, resolved_session_id, create_if_missing=True)

    background_tasks.add_task(
        run_scan_in_background,
        request.target,
        request.mode,
        request.scanners,
        resolved_session_id,
        current_user.id,
    )
    return {
        "message": f"Scan initiated on {request.target}",
        "session_id": resolved_session_id,
    }


@app.post("/ai/explain")
async def ai_explain(
    request: ChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Endpoint for the AI Chat interface to explain logs or answer questions.
    """
    resolved_session_id = _sanitize_session_id(request.session_id)
    scan_record = _assert_session_access(db, current_user, resolved_session_id, create_if_missing=True)

    logs_context = "\n".join(request.logs[-80:])

    findings = state.get_findings(resolved_session_id)[-120:]
    if not findings:
        findings = json_loads_safe(scan_record.findings_json, [])[-120:]

    findings_context_lines = []
    for finding in findings:
        finding_type = finding.get("finding_type", "unknown")
        value = finding.get("finding_value", "N/A")
        target = finding.get("target", "")
        risk = finding.get("risk_level", "unknown")
        cve = finding.get("cve_id", "")
        findings_context_lines.append(
            f"- {finding_type} | value={value} | risk={risk} | target={target} | cve={cve}"
        )
    findings_context = "\n".join(findings_context_lines)

    zeroday_matches = state.get_zeroday_matches(resolved_session_id)
    if not zeroday_matches:
        zeroday_matches = json_loads_safe(scan_record.zeroday_matches_json, [])

    remediation = state.get_remediation(resolved_session_id)
    if not remediation:
        remediation = json_loads_safe(scan_record.remediation_json, {})

    nvd_lines = []
    unverified_lines = []
    for zd in zeroday_matches[:20]:
        score = f" CVSS:{zd.get('cvss_score')}" if zd.get("cvss_score") else ""
        line = (
            f"- {zd.get('cve_id') or 'N/A'}{score} ({zd.get('published') or 'unknown date'}): "
            f"{str(zd.get('description',''))[:200]}"
            f" | Source: {zd.get('source')} ({zd.get('source_url')})"
        )
        if zd.get("intel_type") == "unverified_web":
            unverified_lines.append(line)
        else:
            nvd_lines.append(line)

    combined_context = (
        "Recent Logs:\n"
        + logs_context
        + "\n\nStructured Findings:\n"
        + (findings_context or "No structured findings captured.")
        + "\n\nRecent Zero-Day / Threat Intelligence (NVD - Verified):\n"
        + ("\n".join(nvd_lines) or "No recent CVEs found.")
        + "\n\n[UNVERIFIED EXTERNAL WEB INTEL - NOT CONFIRMED, MAY CONTAIN FALSE POSITIVES]:\n"
        + ("\n".join(unverified_lines) or "No unverified web intel found.")
        + "\n[END UNVERIFIED INTEL]"
        + "\n\nCVE Remediation Data:\n"
        + (
            "\n".join(
                f"- {cve}: CVSS {d.get('cvss_score','N/A')} | {d.get('description','')[:150]} | "
                f"CWEs: {', '.join(d.get('cwes', [])) or 'N/A'} | "
                + (f"GHSA patch: {', '.join(d['ghsa']['patched_versions']) or 'see advisory'}" if d.get('ghsa') and d['ghsa'].get('patched_versions') is not None else "")
                for cve, d in list(remediation.items())[:15]
            ) or "No CVE remediation data available."
        )
    )
    answer = await ai_agent.answer_question_async(
        combined_context,
        request.question,
        session_id=resolved_session_id,
    )
    return {"answer": answer}


@app.get("/ai/reasoning")
async def get_reasoning(
    session_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    resolved_session_id = _sanitize_session_id(session_id)
    scan_record = _assert_session_access(db, current_user, resolved_session_id, create_if_missing=True)

    reasoning = state.get_reasoning(resolved_session_id)
    if not reasoning or reasoning.strip() == "Waiting for active scan analysis...":
        if scan_record.reasoning:
            reasoning = scan_record.reasoning

    return {"reasoning": reasoning}


@app.post("/api/scan/stop")
async def stop_scan(
    session_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    resolved_session_id = _sanitize_session_id(session_id)
    _assert_session_access(db, current_user, resolved_session_id, create_if_missing=False)
    state.stop_scan(resolved_session_id)
    return {"message": "Scan stop requested.", "session_id": resolved_session_id}


@app.delete("/api/session")
async def terminate_session(
    session_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    resolved_session_id = _sanitize_session_id(session_id)
    _assert_session_access(db, current_user, resolved_session_id, create_if_missing=False)
    state.stop_scan(resolved_session_id)
    state.clear_session(resolved_session_id)
    # Remove DB record
    from orchestrator.core.db import ScanSession, select
    with db:
        stmt = select(ScanSession).where(ScanSession.session_id == resolved_session_id)
        record = db.execute(stmt).scalar_one_or_none()
        if record:
            db.delete(record)
            db.commit()
    return {"message": "Session terminated.", "session_id": resolved_session_id}


@app.get("/api/scanners")
async def get_scanners(current_user: User = Depends(get_current_user)):
    _ = current_user
    from orchestrator.core import registry

    return [{"name": sc["name"], "enabled": sc["enabled"]} for sc in registry.SCANNERS]


@app.get("/api/checks/catalog")
async def get_checks_catalog_endpoint(current_user: User = Depends(get_current_user)):
    _ = current_user
    return {"checks": get_checks_catalog()}


@app.get("/api/checks/coverage")
async def get_checks_coverage(
    scanners: Optional[str] = Query(default="all"),
    session_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    resolved_session_id = _sanitize_session_id(session_id)
    scan_record = _assert_session_access(db, current_user, resolved_session_id, create_if_missing=True)

    if scanners == "__none__":
        selected_scanners = []
    else:
        selected_scanners = dependencies.resolve_enabled_scanners(scanners or "all")

    findings = state.get_findings(resolved_session_id)
    if not findings:
        findings = json_loads_safe(scan_record.findings_json, [])

    return evaluate_check_coverage(selected_scanners, findings=findings)


@app.get("/api/report/pdf")
async def download_pdf_report(
    session_id: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    resolved_session_id = _sanitize_session_id(session_id)
    scan_record = _assert_session_access(db, current_user, resolved_session_id, create_if_missing=False)

    scan_metadata = state.get_scan_metadata(resolved_session_id)
    findings = state.get_findings(resolved_session_id)
    reasoning = state.get_reasoning(resolved_session_id)
    searchsploit_matches = state.get_searchsploit_matches(resolved_session_id)
    zeroday_matches = state.get_zeroday_matches(resolved_session_id)
    remediation = state.get_remediation(resolved_session_id)
    logs = state.get_logs(resolved_session_id, limit=500)

    if not scan_metadata:
        scan_metadata = {
            "target": scan_record.target,
            "mode": scan_record.mode,
            "scanners": scan_record.scanners,
            "status": scan_record.status,
            "error": scan_record.error,
            "started_at": scan_record.started_at,
            "ended_at": scan_record.ended_at,
        }
    if not findings:
        findings = json_loads_safe(scan_record.findings_json, [])
    if not searchsploit_matches:
        searchsploit_matches = json_loads_safe(scan_record.searchsploit_matches_json, [])
    if not zeroday_matches:
        zeroday_matches = json_loads_safe(scan_record.zeroday_matches_json, [])
    if not remediation:
        remediation = json_loads_safe(scan_record.remediation_json, {})
        reasoning = scan_record.reasoning
    if not logs:
        logs = json_loads_safe(scan_record.logs_json, [])

    if not scan_metadata and not findings and not logs:
        raise HTTPException(status_code=404, detail="No scan data found for this session.")

    try:
        from orchestrator.core.reporting import generate_pdf_report

        scanners_arg = str(scan_metadata.get("scanners", "all") or "all")
        if scanners_arg == "__none__":
            selected_scanners = []
        else:
            selected_scanners = dependencies.resolve_enabled_scanners(scanners_arg)
        checklist_coverage = evaluate_check_coverage(selected_scanners, findings=findings)

        pdf_bytes = generate_pdf_report(
            session_id=resolved_session_id,
            scan_metadata=scan_metadata,
            findings=findings,
            reasoning=reasoning,
            logs=logs,
            checklist_coverage=checklist_coverage,
            searchsploit_matches=searchsploit_matches,
            zeroday_matches=zeroday_matches,
            remediation=remediation,
        )
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="PDF generation dependency missing. Install backend requirements.",
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {exc}")

    target = _safe_filename_fragment(str(scan_metadata.get("target", "scan")))
    filename = f"astra-report-{target}-{resolved_session_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
