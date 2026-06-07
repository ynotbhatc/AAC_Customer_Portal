"""Unauthenticated tenant-user auth endpoints.

Exposed under /api/portal/v1/auth. The login flow goes:

    POST /auth/login       (tenant_id + email + password)
        → returns session_token (mfa_verified=false if MFA enabled)
    [PR 4: POST /auth/totp/verify with the session, sets mfa_verified=true]
    GET  /me  / any other endpoint
        Authorization: Bearer <session_token>

Password reset is two-step:
    Operator: POST /admin/v1/tenants/{tid}/users/{uid}/issue-password-reset
        → returns the one-time token to hand to the user OOB
    User:     POST /auth/password-reset/confirm
        body = { reset_token, new_password }
        → consumes the token, sets password_hash, revokes all sessions
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any
from uuid import UUID

import asyncpg
import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from ..core.config import get_settings
from ..core.rate_limit import rate_limit
from ..core.passwords import (
    PasswordTooWeak,
    check_strength,
    hash_password,
    verify_password,
)
from ..core.portal_db import get_portal_pool
from ..core.sessions import (
    _client_ip,
    create_session,
    require_tenant_user,
    revoke_all_sessions_for_user,
)
from ..core.totp import verify_totp
from ..models.tenant_mfa import TotpVerifyRequest
from ..models.tenant_session import (
    LoginRequest,
    PasswordResetConfirm,
    SessionCreated,
)


router = APIRouter(prefix="/portal/v1/auth", tags=["portal:auth"])


# ── login ─────────────────────────────────────────────────────────────
@router.post("/login", response_model=SessionCreated, status_code=201)
async def login(
    body: LoginRequest,
    request: Request,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    _rate: Annotated[None, Depends(rate_limit("10/minute"))],
) -> SessionCreated:
    # Look up the user. Single round-trip; we deliberately do NOT
    # disclose whether the email vs the tenant vs the password was
    # wrong — all four bad-input cases return the same 401.
    row = await pool.fetchrow(
        """
        SELECT id, tenant_id, password_hash, mfa_required, disabled_at
          FROM tenant_users
         WHERE tenant_id = $1 AND email = $2
        """,
        body.tenant_id,
        str(body.email),
    )
    bad = HTTPException(status_code=401, detail="invalid credentials")
    if row is None or row["disabled_at"] is not None or row["password_hash"] is None:
        # Still spend the bcrypt time even on miss, to prevent timing
        # leaks that distinguish "user exists" from "user doesn't".
        await verify_password(body.password, _DUMMY_HASH)
        raise bad
    if not await verify_password(body.password, row["password_hash"]):
        raise bad

    # MFA: if the user's required_mfa flag is on, the session is
    # created with mfa_verified=False. The PR 4 endpoint flips it
    # on after TOTP verification. Until PR 4 lands, mfa_required
    # users can only call endpoints that don't gate on MFA — but
    # the policy endpoints (PR 5+) WILL gate on it.
    session_token, expires_at = await create_session(
        pool,
        tenant_user_id=row["id"],
        mfa_verified=not row["mfa_required"],
        ip=await _client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    # Stamp the user's last_login_at — best-effort.
    try:
        await pool.execute(
            "UPDATE tenant_users SET last_login_at = now() WHERE id = $1",
            row["id"],
        )
    except Exception:
        pass

    return SessionCreated(
        session_token=session_token,
        expires_at=expires_at,
        mfa_required=row["mfa_required"],
        mfa_verified=not row["mfa_required"],
    )


# Pre-generated bcrypt hash for an arbitrary throwaway value, used to
# burn equivalent CPU time when the user doesn't exist (constant-time
# behaviour from the client's perspective).
_DUMMY_HASH = "$2b$12$YgjFp9TZAJTAOaKfDB9q6e8.dWWlmsiTzczWPpDBLwTZIWmS6jepi"


# ── password reset (confirm) ──────────────────────────────────────────
@router.post("/password-reset/confirm", status_code=204, response_class=Response, response_model=None)
async def password_reset_confirm(
    body: PasswordResetConfirm,
    request: Request,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    _rate: Annotated[None, Depends(rate_limit("5/minute"))],
) -> None:
    try:
        check_strength(body.new_password)
    except PasswordTooWeak as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if "." not in body.reset_token:
        raise HTTPException(status_code=400, detail="malformed reset token")
    reset_id_str, secret = body.reset_token.split(".", 1)
    try:
        reset_id = UUID(reset_id_str)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="malformed reset token") from exc

    row = await pool.fetchrow(
        """
        SELECT id, tenant_user_id, token_hash, expires_at, used_at
          FROM tenant_user_password_resets
         WHERE id = $1
        """,
        reset_id,
    )
    bad = HTTPException(status_code=400, detail="reset token invalid or expired")
    if row is None or row["used_at"] is not None:
        raise bad
    if row["expires_at"] < datetime.now(tz=timezone.utc):
        raise bad
    if not await verify_password(secret, row["token_hash"]):
        raise bad

    new_hash = hash_password(body.new_password)
    # Single transaction: stamp the reset row used, update the user's
    # password_hash, revoke all the user's existing sessions. Anything
    # less invites a race where someone with an old session keeps it.
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "UPDATE tenant_user_password_resets SET used_at = now() WHERE id = $1",
                reset_id,
            )
            await conn.execute(
                "UPDATE tenant_users SET password_hash = $1 WHERE id = $2",
                new_hash,
                row["tenant_user_id"],
            )
            await conn.execute(
                """
                UPDATE tenant_user_sessions
                   SET revoked_at = now(),
                       revoked_reason = COALESCE(revoked_reason, 'password_reset')
                 WHERE tenant_user_id = $1 AND revoked_at IS NULL
                """,
                row["tenant_user_id"],
            )


# ── login-time MFA verification ───────────────────────────────────────
@router.post("/totp/verify", status_code=204, response_class=Response, response_model=None)
async def totp_verify(
    body: TotpVerifyRequest,
    request: Request,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    _rate: Annotated[None, Depends(rate_limit("10/minute"))],
) -> None:
    """Second factor after a successful password login. Authenticated
    via the partially-verified session (mfa_verified=false) issued by
    /auth/login. On success, flips that session's mfa_verified to true.

    Accepts either a 6-digit TOTP code OR a backup code. TOTP path
    first because it's overwhelmingly the common case; backup-code
    iteration is small (10 rows max) so the fallback is cheap.
    """
    if tenant_user.get("mfa_verified"):
        # Idempotent: already verified, nothing to do.
        return None
    if not tenant_user.get("mfa_required"):
        raise HTTPException(status_code=409, detail="mfa not required for this user")

    # Try TOTP factor first.
    totp_row = await pool.fetchrow(
        """
        SELECT id, secret_hash
          FROM tenant_user_mfa_factors
         WHERE tenant_user_id = $1
           AND factor_type = 'totp'
           AND factor_label != 'pending_setup'
           AND revoked_at IS NULL
         LIMIT 1
        """,
        tenant_user["tenant_user_id"],
    )
    consumed_factor_id: UUID | None = None

    if totp_row is not None and verify_totp(secret=totp_row["secret_hash"], code=body.code):
        consumed_factor_id = totp_row["id"]
    else:
        # Backup code fallback. Iterate the (≤10) active backup rows.
        backup_rows = await pool.fetch(
            """
            SELECT id, secret_hash
              FROM tenant_user_mfa_factors
             WHERE tenant_user_id = $1
               AND factor_type = 'backup_codes'
               AND revoked_at IS NULL
            """,
            tenant_user["tenant_user_id"],
        )
        for r in backup_rows:
            if bcrypt.checkpw(body.code.encode("utf-8"), r["secret_hash"].encode("utf-8")):
                consumed_factor_id = r["id"]
                # Burn the backup code immediately — single use.
                await pool.execute(
                    """
                    UPDATE tenant_user_mfa_factors
                       SET revoked_at = now(),
                           last_used_at = now()
                     WHERE id = $1
                    """,
                    consumed_factor_id,
                )
                break

    if consumed_factor_id is None:
        raise HTTPException(status_code=400, detail="incorrect code")

    # Flip the session's mfa_verified bit AND stamp last_used on the
    # TOTP factor (idempotent if it was a backup code — we already
    # stamped revoked_at + last_used above).
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "UPDATE tenant_user_sessions SET mfa_verified = true WHERE id = $1",
                tenant_user["session_id"],
            )
            if totp_row is not None and consumed_factor_id == totp_row["id"]:
                await conn.execute(
                    "UPDATE tenant_user_mfa_factors SET last_used_at = now() WHERE id = $1",
                    consumed_factor_id,
                )
