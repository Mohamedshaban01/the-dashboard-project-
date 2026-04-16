"""
User model for authentication and RBAC.
Phase 3.1 — Found 404 Hardening Plan.
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Enum, String
from app.core.database import Base


class UserRole(str, enum.Enum):
    VIEWER = "VIEWER"    # GET everything, no mutations
    ANALYST = "ANALYST"  # GET + trigger scans + update vuln status
    ADMIN = "ADMIN"      # Everything + target CRUD + user management


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.VIEWER)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)
    # Force password change on first login (set True for seeded admin)
    force_password_change = Column(Boolean, default=False, nullable=False)
    disabled = Column(Boolean, default=False, nullable=False)
