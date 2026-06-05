"""Pydantic models for TOTP enrollment + login MFA verification."""
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class TotpSetupResponse(BaseModel):
    """Returned by POST /portal/v1/me/mfa/totp/setup. The user pastes the
    URI (or scans the QR the frontend renders from it) into their
    authenticator app, then confirms by sending a code back."""
    factor_id: UUID
    otpauth_uri: str = Field(
        ...,
        description="otpauth:// provisioning URI — frontend renders as QR.",
    )
    secret: str = Field(
        ...,
        description="Base32 TOTP secret. Shown ONCE so the user can paste "
        "it into apps that don't support QR. Cannot be retrieved later.",
    )


class TotpConfirmRequest(BaseModel):
    """User submits the 6-digit code their authenticator generated for
    the just-issued secret to prove the enrollment worked."""
    factor_id: UUID
    code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class BackupCodesResponse(BaseModel):
    """Returned exactly once when TOTP enrollment is confirmed. The user
    prints them and stores them somewhere offline."""
    backup_codes: list[str] = Field(
        ...,
        description="One-time recovery codes, shown ONCE. Each works "
        "for exactly one login if the authenticator is lost.",
    )


class TotpVerifyRequest(BaseModel):
    """POSTed during login after the password step to flip the session's
    mfa_verified flag. Accepts either a fresh TOTP code OR a backup
    code (the server tries TOTP first, then falls back to backup)."""
    code: str = Field(..., min_length=6, max_length=64)


class MfaFactorSummary(BaseModel):
    """Public view of an enrolled factor — secrets never leave the DB."""
    id: UUID
    factor_type: Literal["totp", "webauthn", "backup_codes"]
    factor_label: str | None = None
    enrolled_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
