"""
FastAPI dependency injectors for authentication and RBAC.
Phase 3.1 — Found 404 Hardening Plan.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_token
from app.models.user import User, UserRole

_bearer = HTTPBearer(auto_error=True)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    """
    Validate the Bearer JWT and return the authenticated User.
    Raises HTTP 401 for missing/invalid tokens and HTTP 403 for disabled accounts.
    """
    exc_401 = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(credentials.credentials)
        email: str = payload.get("sub")
        if not email:
            raise exc_401
    except JWTError:
        raise exc_401

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise exc_401
    if user.disabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
    return user


def require_role(*roles: UserRole):
    """
    Factory that returns a dependency enforcing one of the given roles.

    Usage:
        @router.post("/...", dependencies=[Depends(require_role(UserRole.ADMIN))])
    """
    def _check(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of: {[r.value for r in roles]}",
            )
        return current_user
    return _check
