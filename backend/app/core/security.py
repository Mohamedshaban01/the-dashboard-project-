"""
JWT authentication and password hashing utilities.
Phase 3.1 — Found 404 Hardening Plan.
"""
from datetime import datetime, timedelta
from typing import Optional

import bcrypt as _bcrypt_lib
from jose import JWTError, jwt

from app.core.config import settings


# ── Password helpers ──────────────────────────────────────────────────────────
# Using bcrypt directly to avoid passlib/bcrypt 4.x version conflicts.

def hash_password(plain: str) -> str:
    return _bcrypt_lib.hashpw(plain.encode(), _bcrypt_lib.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt_lib.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ── JWT helpers ───────────────────────────────────────────────────────────────

ALGORITHM = "HS256"


def create_access_token(subject: str, role: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Issue a signed JWT.

    Args:
        subject: The user identifier (email).
        role: The user's RBAC role string.
        expires_delta: Override the default 8-hour TTL.
    """
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=settings.JWT_EXPIRE_HOURS))
    payload = {
        "sub": subject,
        "role": role,
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """
    Decode and validate a JWT.

    Returns:
        The decoded payload dict.

    Raises:
        JWTError: If the token is invalid or expired.
    """
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM])
