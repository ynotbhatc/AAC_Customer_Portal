"""Authenticated tenant-user self-service endpoints.

Exposed under /api/portal/v1/me. Bearer is the session_token from
auth/login. These DO NOT require MFA verification yet — that gate is
added in PR 4 by switching this router's dependency to a stricter
one. Set-password requires the current password (a session hijack
alone shouldn't be able to lock the user out).
"""
from __future__ import annotations

import secrets
from typing import Annotated, Any

import asyncpg
import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Response

from ..core.config import get_settings
from ..core.cookies import clear_csrf_cookie, clear_session_cookie
from ..core.passwords import (
    PasswordTooWeak,
    check_strength,
    hash_password,
    verify_password,
)
from ..core.portal_db import get_portal_pool
from ..core.sessions import (
    require_tenant_user,
    revoke_all_sessions_for_user,
    revoke_session,
)
from ..models.tenant_session import LogoutResult, MeResponse, SetPasswordRequest


router = APIRouter(prefix="/portal/v1/me", tags=["portal:me"])


@router.get("", response_model=MeResponse)
async def me(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
) -> MeResponse:
    return MeResponse(
        tenant_id=tenant_user["tenant_id"],
        user_id=tenant_user["tenant_user_id"],
        email=tenant_user["email"],
        display_name=tenant_user.get("display_name"),
        role=tenant_user["role"],
        mfa_required=tenant_user["mfa_required"],
        mfa_enrolled=tenant_user["mfa_enrolled"],
        mfa_verified=tenant_user["mfa_verified"],
    )


@router.post("/set-password", status_code=204, response_class=Response, response_model=None)
async def set_password(
    body: SetPasswordRequest,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> None:
    try:
        check_strength(body.new_password)
    except PasswordTooWeak as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    row = await pool.fetchrow(
        "SELECT password_hash FROM tenant_users WHERE id = $1",
        tenant_user["tenant_user_id"],
    )
    if row is None or row["password_hash"] is None:
        # No current password set — use the password-reset flow instead.
        raise HTTPException(
            status_code=409,
            detail="no password on file; use the password-reset flow",
        )
    if not await verify_password(body.current_password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="current password incorrect")

    new_hash = hash_password(body.new_password)
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "UPDATE tenant_users SET password_hash = $1 WHERE id = $2",
                new_hash,
                tenant_user["tenant_user_id"],
            )
            # Revoke every OTHER session — keep the current one alive
            # so the user doesn't have to re-login after a password
            # change. Hijack-recovery: the legitimate user can call
            # /logout-all if they suspect compromise.
            await conn.execute(
                """
                UPDATE tenant_user_sessions
                   SET revoked_at = now(),
                       revoked_reason = COALESCE(revoked_reason, 'password_change')
                 WHERE tenant_user_id = $1
                   AND id != $2
                   AND revoked_at IS NULL
                """,
                tenant_user["tenant_user_id"],
                tenant_user["session_id"],
            )


@router.post("/logout", response_model=LogoutResult)
async def logout(
    response: Response,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> LogoutResult:
    await revoke_session(pool, tenant_user["session_id"], reason="user_logout")
    settings = get_settings()
    clear_session_cookie(response, settings)
    clear_csrf_cookie(response, settings)
    return LogoutResult(revoked="session")


@router.post("/logout-all", response_model=LogoutResult)
async def logout_all(
    response: Response,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> LogoutResult:
    await revoke_all_sessions_for_user(
        pool, tenant_user["tenant_user_id"], reason="user_logout_all"
    )
    settings = get_settings()
    clear_session_cookie(response, settings)
    clear_csrf_cookie(response, settings)
    return LogoutResult(revoked="all")
