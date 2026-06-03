"""Pydantic models for tenant-user login, sessions, password reset."""
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from .tenant_user import Role


class LoginRequest(BaseModel):
    tenant_id: UUID
    email: EmailStr
    password: str = Field(..., min_length=1)


class SessionCreated(BaseModel):
    session_token: str = Field(
        ...,
        description="Combined session token (session_id.secret). Send as "
        "Authorization: Bearer <session_token>. Shown only once.",
    )
    expires_at: datetime
    mfa_required: bool
    mfa_verified: bool


class MeResponse(BaseModel):
    """Returned by GET /portal/v1/me — minimal identity payload for the
    browser app to render the header and gate UI affordances."""
    tenant_id: UUID
    user_id: UUID
    email: str
    display_name: str | None = None
    role: Role
    mfa_required: bool
    mfa_verified: bool


class SetPasswordRequest(BaseModel):
    """Self-service password change. Requires the caller's current
    session AND their current password — guards against a hijacked
    session being used to lock the legitimate user out."""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=1)


class PasswordResetIssued(BaseModel):
    """Returned by the admin endpoint when issuing a one-time reset.
    The plaintext `reset_token` is shown ONCE; the operator hands it
    to the tenant user out-of-band (email, ticket comment)."""
    reset_token: str = Field(
        ...,
        description="Single-use plaintext reset token. Shown once; "
        "cannot be retrieved later.",
    )
    expires_at: datetime


class PasswordResetConfirm(BaseModel):
    """Unauthenticated — the token IS the auth. Hits a different
    endpoint than SetPasswordRequest because the user can't log in yet."""
    reset_token: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=1)


class LogoutResult(BaseModel):
    revoked: Literal["session", "all"]
