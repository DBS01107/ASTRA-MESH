from __future__ import annotations

from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from . import state
from .db import (
    ScanSession,
    SessionLocal,
    ensure_scan_session_owner,
    json_dumps_safe,
    list_user_scan_sessions,
)


def _apply_scan_metadata(
    record: ScanSession,
    metadata: Dict[str, Any],
    status_override: Optional[str] = None,
    error_override: Optional[str] = None,
) -> None:
    if metadata:
        record.target = str(metadata.get("target") or record.target or "")
        record.mode = str(metadata.get("mode") or record.mode or "dynamic")
        record.scanners = str(metadata.get("scanners") or record.scanners or "all")
        record.started_at = metadata.get("started_at") or record.started_at
        record.ended_at = metadata.get("ended_at") or record.ended_at
        record.status = str(metadata.get("status") or record.status or "idle")
        record.error = metadata.get("error")

    if status_override:
        record.status = status_override
    if error_override is not None:
        record.error = error_override


def sync_scan_session_from_state(
    user_id: int,
    session_id: str,
    status_override: Optional[str] = None,
    error_override: Optional[str] = None,
) -> None:
    metadata = state.get_scan_metadata(session_id)
    findings = state.get_findings(session_id)
    logs = state.get_logs(session_id, limit=0)
    reasoning = state.get_reasoning(session_id)
    searchsploit_matches = state.get_searchsploit_matches(session_id)
    zeroday_matches = state.get_zeroday_matches(session_id)
    remediation = state.get_remediation(session_id)

    with SessionLocal() as db:
        record = ensure_scan_session_owner(
            db,
            user_id=user_id,
            session_id=session_id,
            create_if_missing=True,
        )
        _apply_scan_metadata(
            record,
            metadata,
            status_override=status_override,
            error_override=error_override,
        )

        record.reasoning = reasoning or ""
        record.finding_count = len(findings)
        record.findings_json = json_dumps_safe(findings, "[]")
        record.logs_json = json_dumps_safe(logs, "[]")
        record.searchsploit_matches_json = json_dumps_safe(searchsploit_matches, "[]")
        record.zeroday_matches_json = json_dumps_safe(zeroday_matches, "[]")
        record.remediation_json = json_dumps_safe(remediation, "{}")
        db.commit()


def touch_user_session(
    db: Session,
    user_id: int,
    session_id: str,
    create_if_missing: bool = True,
) -> ScanSession:
    return ensure_scan_session_owner(
        db,
        user_id=user_id,
        session_id=session_id,
        create_if_missing=create_if_missing,
    )


def list_user_scans(db: Session, user_id: int, limit: int = 50) -> List[ScanSession]:
    return list_user_scan_sessions(db, user_id=user_id, limit=limit)
