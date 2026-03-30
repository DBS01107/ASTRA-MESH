import queue
import threading
from contextvars import ContextVar, Token
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .graph import AstraGraph, graph_db

_DEFAULT_SESSION_ID = "default"
_DEFAULT_REASONING = "Waiting for active scan analysis..."
_MAX_LOG_HISTORY = 2000

_current_session_id: ContextVar[Optional[str]] = ContextVar(
    "astra_current_session_id",
    default=None,
)
_state_lock = threading.RLock()
_reasoning_by_session: Dict[str, str] = {_DEFAULT_SESSION_ID: _DEFAULT_REASONING}
_log_queues_by_session: Dict[str, queue.Queue[str]] = {_DEFAULT_SESSION_ID: queue.Queue()}
_graphs_by_session: Dict[str, AstraGraph] = {_DEFAULT_SESSION_ID: graph_db}
_log_history_by_session: Dict[str, List[str]] = {_DEFAULT_SESSION_ID: []}
_scan_metadata_by_session: Dict[str, Dict[str, Any]] = {}
_findings_by_session: Dict[str, List[Dict[str, Any]]] = {_DEFAULT_SESSION_ID: []}
_searchsploit_matches_by_session: Dict[str, List[Dict[str, Any]]] = {_DEFAULT_SESSION_ID: []}
_zeroday_matches_by_session: Dict[str, List[Dict[str, Any]]] = {_DEFAULT_SESSION_ID: []}
_remediation_by_session: Dict[str, Dict[str, Any]] = {_DEFAULT_SESSION_ID: {}}


def _normalize_session_id(session_id: Optional[str]) -> str:
    if session_id is None:
        return _DEFAULT_SESSION_ID
    normalized = session_id.strip()
    return normalized or _DEFAULT_SESSION_ID


def ensure_session(session_id: Optional[str]) -> str:
    normalized = _normalize_session_id(session_id)
    with _state_lock:
        _reasoning_by_session.setdefault(normalized, _DEFAULT_REASONING)
        _log_queues_by_session.setdefault(normalized, queue.Queue())
        _log_history_by_session.setdefault(normalized, [])
        _findings_by_session.setdefault(normalized, [])
        _searchsploit_matches_by_session.setdefault(normalized, [])
        _zeroday_matches_by_session.setdefault(normalized, [])
        _remediation_by_session.setdefault(normalized, {})
    return normalized


def _drain_queue(log_queue: "queue.Queue[str]") -> None:
    while True:
        try:
            log_queue.get_nowait()
        except queue.Empty:
            return


def set_current_session(session_id: Optional[str]) -> Token:
    normalized = ensure_session(session_id)
    return _current_session_id.set(normalized)


def reset_current_session(token: Token) -> None:
    _current_session_id.reset(token)


def get_current_session() -> str:
    return ensure_session(_current_session_id.get())


def get_log_queue(session_id: Optional[str] = None) -> queue.Queue[str]:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    return _log_queues_by_session[normalized]


def push_log(text: str, session_id: Optional[str] = None) -> None:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    _log_queues_by_session[normalized].put(text)
    with _state_lock:
        history = _log_history_by_session.setdefault(normalized, [])
        history.append(text.rstrip("\n"))
        if len(history) > _MAX_LOG_HISTORY:
            del history[:-_MAX_LOG_HISTORY]


def update_reasoning(text: str, session_id: Optional[str] = None) -> None:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        _reasoning_by_session[normalized] = text


def get_reasoning(session_id: Optional[str] = None) -> str:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    return _reasoning_by_session.get(normalized, _DEFAULT_REASONING)


def get_graph(session_id: Optional[str] = None) -> AstraGraph:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        graph = _graphs_by_session.get(normalized)
        if graph is None:
            graph = AstraGraph(isolated=True)
            _graphs_by_session[normalized] = graph
        return graph


def get_graph_for_current_session() -> AstraGraph:
    return get_graph(get_current_session())


def start_scan(
    target: str,
    mode: str,
    scanners: Optional[str],
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    started_at = datetime.now(timezone.utc).isoformat()
    scan_metadata = {
        "target": target,
        "mode": mode,
        "scanners": scanners or "all",
        "started_at": started_at,
        "ended_at": None,
        "status": "running",
        "error": None,
    }
    with _state_lock:
        _scan_metadata_by_session[normalized] = scan_metadata
        _findings_by_session[normalized] = []
        _searchsploit_matches_by_session[normalized] = []
        _zeroday_matches_by_session[normalized] = []
        _remediation_by_session[normalized] = {}
        _log_history_by_session[normalized] = []
        _reasoning_by_session[normalized] = _DEFAULT_REASONING
        session_queue = _log_queues_by_session.setdefault(normalized, queue.Queue())
        _drain_queue(session_queue)

        previous_graph = _graphs_by_session.get(normalized)
        if previous_graph is not None and previous_graph is not graph_db:
            try:
                previous_graph.close()
            except Exception:
                pass
        _graphs_by_session[normalized] = AstraGraph(isolated=True)
    return dict(scan_metadata)


def finish_scan(
    session_id: Optional[str] = None,
    status: str = "completed",
    error: Optional[str] = None,
) -> Dict[str, Any]:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    ended_at = datetime.now(timezone.utc).isoformat()
    with _state_lock:
        metadata = _scan_metadata_by_session.get(normalized, {})
        metadata["ended_at"] = ended_at
        metadata["status"] = status
        metadata["error"] = error
        _scan_metadata_by_session[normalized] = metadata
        return dict(metadata)


def _serialize_finding(finding: Any) -> Dict[str, Any]:
    if isinstance(finding, dict):
        data = dict(finding)
    else:
        data = {
            "id": getattr(finding, "id", ""),
            "source_tool": getattr(finding, "source_tool", ""),
            "finding_type": getattr(finding, "finding_type", ""),
            "target": getattr(finding, "target", ""),
            "finding_value": getattr(finding, "finding_value", None),
            "severity": getattr(finding, "severity", None),
            "capability": getattr(finding, "capability", None),
            "risk_level": getattr(finding, "risk_level", None),
            "port": getattr(finding, "port", None),
            "service": getattr(finding, "service", None),
            "version": getattr(finding, "version", None),
            "os": getattr(finding, "os", None),
            "cve_id": getattr(finding, "cve_id", None),
            "cvss_score": getattr(finding, "cvss_score", None),
            "details": getattr(finding, "details", {}) or {},
        }
    if not isinstance(data.get("details"), dict):
        data["details"] = {}
    return data


def add_finding(finding: Any, session_id: Optional[str] = None) -> None:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    serialized = _serialize_finding(finding)
    finding_id = serialized.get("id")

    with _state_lock:
        findings = _findings_by_session.setdefault(normalized, [])
        if finding_id and any(item.get("id") == finding_id for item in findings):
            return
        findings.append(serialized)


def get_findings(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        return [dict(item) for item in _findings_by_session.get(normalized, [])]


def update_searchsploit_matches(
    matches: List[Dict[str, Any]],
    session_id: Optional[str] = None,
) -> None:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    sanitized: List[Dict[str, Any]] = []
    for match in matches or []:
        if not isinstance(match, dict):
            continue
        sanitized.append(
            {
                "title": str(match.get("title", "") or ""),
                "edb_id": str(match.get("edb_id", "") or ""),
                "path": str(match.get("path", "") or ""),
                "type": str(match.get("type", "") or ""),
                "platform": str(match.get("platform", "") or ""),
                "date": str(match.get("date", "") or ""),
                "service": str(match.get("service", "") or ""),
                "version": str(match.get("version", "") or ""),
                "query": str(match.get("query", "") or ""),
                "target": str(match.get("target", "") or ""),
            }
        )
    with _state_lock:
        _searchsploit_matches_by_session[normalized] = sanitized


def get_searchsploit_matches(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        return [dict(item) for item in _searchsploit_matches_by_session.get(normalized, [])]


def get_logs(session_id: Optional[str] = None, limit: int = 400) -> List[str]:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        history = _log_history_by_session.get(normalized, [])
        if limit <= 0:
            return list(history)
        return list(history[-limit:])


def get_scan_metadata(session_id: Optional[str] = None) -> Dict[str, Any]:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        return dict(_scan_metadata_by_session.get(normalized, {}))


def is_scan_running(session_id: Optional[str] = None) -> bool:
    metadata = get_scan_metadata(session_id)
    return metadata.get("status") == "running"


def stop_scan(session_id: Optional[str] = None) -> None:
    """Mark a running scan as stopped. The background thread will detect this and exit."""
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        metadata = _scan_metadata_by_session.get(normalized, {})
        if metadata.get("status") == "running":
            metadata["status"] = "stopped"
            _scan_metadata_by_session[normalized] = metadata


def clear_session(session_id: Optional[str] = None) -> None:
    """Wipe all in-memory state for a session (terminate)."""
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        _scan_metadata_by_session.pop(normalized, None)
        _findings_by_session[normalized] = []
        _searchsploit_matches_by_session[normalized] = []
        _zeroday_matches_by_session[normalized] = []
        _remediation_by_session[normalized] = {}
        _log_history_by_session[normalized] = []
        _reasoning_by_session[normalized] = _DEFAULT_REASONING
        q = _log_queues_by_session.get(normalized)
        if q:
            _drain_queue(q)
        graph = _graphs_by_session.pop(normalized, None)
        if graph and graph is not graph_db:
            try:
                graph.close()
            except Exception:
                pass


def update_zeroday_matches(
    matches: List[Dict[str, Any]],
    session_id: Optional[str] = None,
) -> None:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    sanitized: List[Dict[str, Any]] = []
    for match in matches or []:
        if not isinstance(match, dict):
            continue
        sanitized.append({
            "cve_id": str(match.get("cve_id", "") or ""),
            "published": str(match.get("published", "") or ""),
            "description": str(match.get("description", "") or ""),
            "cvss_score": match.get("cvss_score"),
            "cvss_vector": str(match.get("cvss_vector", "") or ""),
            "keyword": str(match.get("keyword", "") or ""),
            "source": str(match.get("source", "") or ""),
            "source_url": str(match.get("source_url", "") or ""),
            "intel_type": str(match.get("intel_type", "nvd") or "nvd"),
        })
    with _state_lock:
        _zeroday_matches_by_session[normalized] = sanitized


def get_zeroday_matches(session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        return [dict(item) for item in _zeroday_matches_by_session.get(normalized, [])]


def update_remediation(
    cve_id: str,
    data: Dict[str, Any],
    session_id: Optional[str] = None,
) -> None:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        _remediation_by_session.setdefault(normalized, {})[cve_id.upper()] = data


def get_remediation(session_id: Optional[str] = None) -> Dict[str, Any]:
    normalized = ensure_session(session_id if session_id is not None else get_current_session())
    with _state_lock:
        return dict(_remediation_by_session.get(normalized, {}))
