"""TOTP MFA helpers (RFC 6238).

pyotp does the math; this module wraps it for the patterns the routers
need:
  - generate a base32 secret + the otpauth:// provisioning URI
  - verify a submitted 6-digit code with a small clock-skew window
  - generate one-time backup codes for account recovery

Backup codes are 10 random url-safe strings (8 chars, ~48 bits each —
plenty for a one-time use). Each is stored as its own row in
tenant_user_mfa_factors with factor_type='backup_codes' so consumption
is one UPDATE (set revoked_at). We do not allow re-use; once revoked,
the code is dead.
"""
from __future__ import annotations

import secrets

import pyotp

# RFC 6238 default window. We accept the current step and the one before
# (so a code is good for ~60 seconds total) — guards against the user
# tapping submit just as the authenticator rolls over.
_VERIFY_WINDOW = 1

# Authenticator-app issuer label shown in the user's app list.
TOTP_ISSUER = "AAC Customer Portal"

_BACKUP_CODE_COUNT = 10
_BACKUP_CODE_BYTES = 6   # → 8 url-safe chars


def new_totp_secret() -> str:
    """Random base32 secret (160 bits, RFC 4226 §4 recommendation)."""
    return pyotp.random_base32()


def otpauth_uri(*, secret: str, account_label: str) -> str:
    """Build the otpauth:// URI the authenticator app scans / pastes.

    `account_label` is what the user sees in their app — we use the
    tenant_user's email so they can distinguish multiple AAC enrollments.
    """
    return pyotp.TOTP(secret).provisioning_uri(
        name=account_label,
        issuer_name=TOTP_ISSUER,
    )


def verify_totp(*, secret: str, code: str) -> bool:
    """Check a 6-digit submitted code against the secret, ±1 step window."""
    if not code or not code.isdigit() or len(code) != 6:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=_VERIFY_WINDOW)


def new_backup_codes() -> list[str]:
    """Generate the recovery code set shown to the user once at enrollment."""
    return [secrets.token_urlsafe(_BACKUP_CODE_BYTES) for _ in range(_BACKUP_CODE_COUNT)]
