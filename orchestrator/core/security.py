import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import bcrypt
import jwt


JWT_SECRET = os.getenv("ASTRA_JWT_SECRET", "astra-dev-secret-change-me")
JWT_ALGORITHM = os.getenv("ASTRA_JWT_ALGORITHM", "HS256")
JWT_EXPIRE_HOURS = int(os.getenv("ASTRA_JWT_EXPIRE_HOURS", "24"))


class TokenValidationError(Exception):
    pass


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "username": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=max(1, JWT_EXPIRE_HOURS))).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise TokenValidationError(str(exc)) from exc
    if "sub" not in payload:
        raise TokenValidationError("Token payload missing subject.")
    return payload
