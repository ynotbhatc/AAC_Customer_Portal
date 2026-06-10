"""Tenant-user session management.

Sessions are server-side rows in `tenant_user_sessions`. Tokens are
random 256-bit secrets formatted as `{session_id}.{token_secret}`,
where session_id is the row's UUID. The dot-separated format lets the
auth dependency look up exactly one row in the hot path instead of
iterating every active session for a user.

Verification chain (request → user):

    Authorization: Bearer <session_id>.<token_secret>
        → row = SELECT * FROM tenant_user_sessions WHERE id = session_id
        → reject if revoked_at IS NOT NULL or expires_at < now()
        → bcrypt verify token_secret against row.session_token_hash
        → load tenant_user, reject if disabled_at IS NOT NULL
        → return {tenant_user, session_id}

bcrypt verify happens off the event loop. Updating last_used_at + IP
is best-effort and never blocks the request.
"""
from __future__ import annotations

import asyncio
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any
from uuid import UUID

import asyncpg
import bcrypt
from fastapi import Depends, Header, HTTPException, Request

from .config import get_settings
from .cookies import read_session_cookie
from .portal_db import get_portal_pool


_TOKEN_SECRET_BYTES = 32  # 256 bits → 43 url-safe chars
_BEARER_PREFIX = "bearer "


def _generate_session_token() -> tuple[str, str]:
    """Return (secret_for_client, hash_for_db). Caller adds the session UUID."""
    secret = secrets.token_urlsafe(_TOKEN_SECRET_BYTES)
    hashed = bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    return secret, hashed


async def _client_ip(request: Request) -> str | None:
    # Same logic as tenant_auth — trust XFF if set, else socket peer.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


async def create_session(
    pool: asyncpg.Pool,
    *,
    tenant_user_id: UUID,
    mfa_verified: bool,
    ip: str | None,
    user_agent: str | None,
) -> tuple[str, datetime]:
    """Insert a new session row. Returns (combined_token, expires_at).

    `combined_token` is what the client sends in Authorization: Bearer.
    It is shown exactly once — only the bcrypt hash is persisted.
    """
    s = get_settings()
    secret, hashed = _generate_session_token()
    expires = datetime.now(tz=timezone.utc) + timedelta(hours=s.session_lifetime_hours)

    row = await pool.fetchrow(
        """
        INSERT INTO tenant_user_sessions
            (tenant_user_id, session_token_hash, mfa_verified,
             expires_at, last_used_from_ip, user_agent)
        VALUES ($1, $2, $3, $4, $5::inet, $6)
        RETURNING id
        """,
        tenant_user_id,
        hashed,
        mfa_verified,
        expires,
        ip,
        user_agent,
    )
    combined = f"{row['id']}.{secret}"
    return combined, expires


async def revoke_session(pool: asyncpg.Pool, session_id: UUID, reason: str | None = None) -> None:
    await pool.execute(
        """
        UPDATE tenant_user_sessions
           SET revoked_at = now(),
               revoked_reason = COALESCE(revoked_reason, $2)
         WHERE id = $1
           AND revoked_at IS NULL
        """,
        session_id,
        reason,
    )


async def revoke_all_sessions_for_user(
    pool: asyncpg.Pool, tenant_user_id: UUID, reason: str
) -> None:
    """Used by password change and by the operator force-logout endpoint."""
    await pool.execute(
        """
        UPDATE tenant_user_sessions
           SET revoked_at = now(),
               revoked_reason = COALESCE(revoked_reason, $2)
         WHERE tenant_user_id = $1
           AND revoked_at IS NULL
        """,
        tenant_user_id,
        reason,
    )


def _extract_session_token(
    request: Request,
    authorization: str | None,
) -> str:
    """Return the raw session token from cookie OR Authorization header.

    Cookie wins when both are present — phase N+1 frontend will only
    send the cookie, but during the transition window a misconfigured
    client could send both; preferring the cookie matches the
    longer-term path. Raises 401 if neither source has a token.
    """
    settings = get_settings()
    cookie_token = read_session_cookie(request, settings)
    if cookie_token:
        return cookie_token
    if not authorization or not authorization.lower().startswith(_BEARER_PREFIX):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return authorization[len(_BEARER_PREFIX):].strip()


async def _resolve_bearer(
    request: Request,
    authorization: str | None,
    pool: asyncpg.Pool,
) -> dict[str, Any]:
    bearer = _extract_session_token(request, authorization)
    if "." not in bearer:
        raise HTTPException(status_code=401, detail="malformed session token")
    session_id_str, secret = bearer.split(".", 1)
    try:
        session_id = UUID(session_id_str)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="malformed session token") from exc

    # Single-row lookup — the session_id in the token routes us directly
    # to the candidate row. We never scan.
    row = await pool.fetchrow(
        """
        SELECT s.id AS session_id, s.tenant_user_id, s.session_token_hash,
               s.mfa_verified, s.expires_at, s.revoked_at,
               u.tenant_id, u.email::text AS email, u.role,
               u.mfa_required, u.mfa_enrolled, u.disabled_at, u.display_name
          FROM tenant_user_sessions s
          JOIN tenant_users u ON u.id = s.tenant_user_id
         WHERE s.id = $1
        """,
        session_id,
    )
    if row is None:
        raise HTTPException(status_code=401, detail="invalid session")
    if row["revoked_at"] is not None:
        raise HTTPException(status_code=401, detail="session revoked")
    if row["expires_at"] < datetime.now(tz=timezone.utc):
        raise HTTPException(status_code=401, detail="session expired")
    if row["disabled_at"] is not None:
        raise HTTPException(status_code=401, detail="user disabled")

    ok = await asyncio.to_thread(
        bcrypt.checkpw, secret.encode("utf-8"), row["session_token_hash"].encode("utf-8")
    )
    if not ok:
        raise HTTPException(status_code=401, detail="invalid session")

    # Best-effort last-used stamp.
    ip = await _client_ip(request)
    try:
        await pool.execute(
            """
            UPDATE tenant_user_sessions
               SET last_used_at = now(),
                   last_used_from_ip = $1::inet
             WHERE id = $2
            """,
            ip,
            row["session_id"],
        )
    except Exception:
        pass

    return {
        "session_id": row["session_id"],
        "tenant_user_id": row["tenant_user_id"],
        "tenant_id": row["tenant_id"],
        "email": row["email"],
        "display_name": row["display_name"],
        "role": row["role"],
        "mfa_required": row["mfa_required"],
        "mfa_enrolled": row["mfa_enrolled"],
        "mfa_verified": row["mfa_verified"],
    }


async def require_tenant_user(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """FastAPI dependency that returns the authenticated tenant_user dict.

    Use this on every customer-facing portal endpoint that needs a
    logged-in user. Does NOT enforce MFA — endpoints requiring MFA
    must use `require_tenant_user_mfa` instead.

    Stashes the resolved user on `request.state.tenant_user` so the
    AuditMiddleware can populate tenant_id / tenant_user_id on
    system_audit_log rows for this request. See P0-B (#47) for the
    audit infrastructure this completes.
    """
    user = await _resolve_bearer(request, authorization, pool)
    request.state.tenant_user = user
    return user


async def require_tenant_user_mfa(
    request: Request,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
) -> dict[str, Any]:
    """Stricter version of require_tenant_user that rejects sessions
    whose MFA step is not complete (when MFA is required for the user).

    Use this on any endpoint that writes policy, changes RBAC, or
    performs sensitive operations. Sessions where mfa_required=true
    are issued with mfa_verified=false; they must POST to
    /auth/totp/verify to flip it on before this dependency will pass.

    `request.state.tenant_user` is already set by require_tenant_user
    (which we depend on); refresh it here too as a defensive measure
    in case someone overrides this dep in a test without overriding
    the parent.
    """
    if tenant_user.get("mfa_required") and not tenant_user.get("mfa_verified"):
        raise HTTPException(status_code=403, detail="mfa verification required")
    request.state.tenant_user = tenant_user
    return tenant_user
