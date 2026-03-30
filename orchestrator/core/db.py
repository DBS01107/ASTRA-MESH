import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    select,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

# ✅ PostgreSQL JSON type
from sqlalchemy.dialects.postgresql import JSON


# =========================
# DATABASE CONFIG
# =========================

DATABASE_URL = os.getenv(
    "ASTRA_DATABASE_URL",
    "postgresql+psycopg2://postgres:password@localhost:5432/astra_db",
)


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# =========================
# MODELS
# =========================

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[Optional[str]] = mapped_column(String(255), unique=True, index=True, nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
    )

    scan_sessions: Mapped[List["ScanSession"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    session_id: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    target: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    mode: Mapped[str] = mapped_column(String(32), default="dynamic", nullable=False)
    scanners: Mapped[str] = mapped_column(Text, default="all", nullable=False)

    status: Mapped[str] = mapped_column(String(32), default="idle", nullable=False)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    started_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ended_at: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    reasoning: Mapped[str] = mapped_column(Text, default="", nullable=False)
    logs_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    findings_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    searchsploit_matches_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    zeroday_matches_json: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    remediation_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
        onupdate=_utcnow,
        nullable=False,
    )

    user: Mapped["User"] = relationship(back_populates="scan_sessions")


# =========================
# ENGINE & SESSION
# =========================

engine = create_engine(DATABASE_URL, future=True)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    class_=Session,
)


# =========================
# EXCEPTIONS
# =========================

class SessionOwnershipError(Exception):
    pass


class SessionNotFoundError(Exception):
    pass


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def json_loads_safe(raw: Optional[str], default: Any) -> Any:
    if raw is None:
        return default
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return default


def json_dumps_safe(value: Any, fallback: str) -> str:
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return fallback


def normalize_username(username: str) -> str:
    return username.strip().lower()


def normalize_email(email: Optional[str]) -> Optional[str]:
    if email is None:
        return None
    cleaned = email.strip().lower()
    return cleaned or None


# =========================
# USER FUNCTIONS
# =========================

def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    return db.get(User, user_id)


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    normalized = normalize_username(username)
    stmt = select(User).where(User.username == normalized)
    return db.execute(stmt).scalar_one_or_none()


def get_user_by_email(db: Session, email: Optional[str]) -> Optional[User]:
    normalized = normalize_email(email)
    if not normalized:
        return None
    stmt = select(User).where(User.email == normalized)
    return db.execute(stmt).scalar_one_or_none()


def create_user(
    db: Session,
    username: str,
    password_hash: str,
    email: Optional[str] = None,
) -> User:
    normalized_username = normalize_username(username)
    normalized_email = normalize_email(email)

    user = User(
        username=normalized_username,
        email=normalized_email,
        password_hash=password_hash,
        is_active=True,
        is_admin=False,
    )

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# =========================
# SESSION FUNCTIONS
# =========================

def ensure_scan_session_owner(
    db: Session,
    user_id: int,
    session_id: str,
    create_if_missing: bool = False,
) -> ScanSession:

    stmt = select(ScanSession).where(ScanSession.session_id == session_id)
    existing = db.execute(stmt).scalar_one_or_none()

    if existing:
        if existing.user_id != user_id:
            raise SessionOwnershipError("Session belongs to another user.")
        return existing

    if not create_if_missing:
        raise SessionNotFoundError("Session not found.")

    created = ScanSession(
        session_id=session_id,
        user_id=user_id,
        status="idle",
        target="",
        mode="dynamic",
        scanners="all",
        reasoning="",
        logs_json="[]",
        findings_json="[]",
        searchsploit_matches_json="[]",
        zeroday_matches_json="[]",
        remediation_json="{}",
    )

    db.add(created)
    db.commit()
    db.refresh(created)

    return created


def list_user_scan_sessions(
    db: Session,
    user_id: int,
    limit: int = 50,
) -> List[ScanSession]:

    stmt = (
        select(ScanSession)
        .where(ScanSession.user_id == user_id)
        .order_by(ScanSession.updated_at.desc())
        .limit(max(1, min(limit, 500)))
    )

    return list(db.execute(stmt).scalars().all())