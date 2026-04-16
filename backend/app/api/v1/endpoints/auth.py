"""
Authentication endpoints.
Phase 3.1 — Found 404 Hardening Plan.

Routes:
  POST /auth/login  → issue JWT
  POST /auth/logout → stateless no-op (client discards token)
  GET  /auth/me     → return current user info
"""
import secrets
import string
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.api.deps import get_current_user
from app.models.user import User, UserRole

router = APIRouter()


# ── Schemas ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    force_password_change: bool


class MeResponse(BaseModel):
    id: str
    email: str
    role: str
    force_password_change: bool
    last_login_at: datetime | None

    class Config:
        from_attributes = True


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _ensure_seed_admin(db: Session) -> None:
    """
    Create a seeded ADMIN user on first boot if no users exist.
    The random password is printed to stdout so ops can capture it from logs.
    """
    if db.query(User).count() == 0:
        password = _generate_password()
        admin = User(
            email="admin@local",
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            force_password_change=True,
        )
        db.add(admin)
        db.commit()
        # Print to stdout so it appears in docker logs
        print(
            f"\n{'='*60}\n"
            f"  FIRST-RUN ADMIN ACCOUNT CREATED\n"
            f"  Email:    admin@local\n"
            f"  Password: {password}\n"
            f"  CHANGE THIS PASSWORD IMMEDIATELY.\n"
            f"{'='*60}\n",
            flush=True,
        )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)):
    """Issue a JWT on successful credential verification."""
    # Seed admin on first call if DB is empty
    _ensure_seed_admin(db)

    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    if user.disabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    user.last_login_at = datetime.utcnow()
    db.commit()

    token = create_access_token(subject=user.email, role=user.role.value)
    return TokenResponse(
        access_token=token,
        role=user.role.value,
        force_password_change=user.force_password_change,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout():
    """
    Stateless logout — the client must discard its token.
    Token invalidation would require a Redis blacklist; implement when needed.
    """
    return None


@router.get("/me", response_model=MeResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return current_user


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: ChangePasswordRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Allow a user to change their own password (required when force_password_change=True)."""
    if not verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password incorrect")
    current_user.password_hash = hash_password(body.new_password)
    current_user.force_password_change = False
    db.commit()
    return None
