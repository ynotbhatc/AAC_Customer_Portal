"""Operator-admin endpoints for tenant_user lifecycle.

All routes require the PORTAL_ADMIN_TOKEN bearer (operator-scope) and
are used during tenant onboarding to seed the first account_owner.

Customer-facing self-service endpoints (login, set-password, MFA
enrollment, "me") are added in PR 3 alongside session management.

This router intentionally does NOT expose password setting. Passwords
are managed via the self-service set-password flow (PR 3), which
requires the user to know their current credential or hit a recovery
link. The operator role can disable users but never sees or sets a
password — keeping the operator-facing surface free of password
material is what makes "operator has no access to customer data"
provable on audit.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import UUID

import asyncpg
import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Path, Query

from ..core.auth import require_admin
from ..core.config import get_settings
from ..core.portal_db import get_portal_pool
from ..models.tenant_session import PasswordResetIssued
from ..models.tenant_user import TenantUser, TenantUserCreate, TenantUserUpdate

router = APIRouter(
    prefix="/admin/v1/tenants",
    tags=["admin:tenant-users"],
    dependencies=[Depends(require_admin)],
)


@router.post(
    "/{tenant_id}/users",
    response_model=TenantUser,
    status_code=201,
)
async def create_tenant_user(
    body: TenantUserCreate,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant_id: UUID = Path(...),
) -> dict:
    # Verify tenant exists and is not deleted — a 404 here is friendlier
    # than letting the FK violation bubble up as a 500.
    tenant = await pool.fetchrow(
        "SELECT id, status FROM tenants WHERE id = $1",
        tenant_id,
    )
    if tenant is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    if tenant["status"] == "deleted":
        raise HTTPException(status_code=409, detail="tenant is deleted")

    try:
        row = await pool.fetchrow(
            """
            INSERT INTO tenant_users
                (tenant_id, email, display_name, role, oidc_subject,
                 mfa_required)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, tenant_id, email::text, display_name, role,
                      oidc_subject, mfa_enrolled, mfa_required,
                      last_login_at, disabled_at, created_at, updated_at
            """,
            tenant_id,
            str(body.email),
            body.display_name,
            body.role,
            body.oidc_subject,
            # account_owner and editor are required to use MFA; viewer is
            # optional. Stored on the row so a later role demotion doesn't
            # silently turn MFA enforcement off — it has to be explicit.
            body.role in ("account_owner", "editor"),
        )
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status_code=409,
            detail=f"email already exists for tenant: {body.email}",
        ) from exc

    return dict(row)


@router.get(
    "/{tenant_id}/users",
    response_model=list[TenantUser],
)
async def list_tenant_users(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant_id: UUID = Path(...),
    include_disabled: bool = Query(default=False),
) -> list[dict]:
    where = "tenant_id = $1"
    args: list = [tenant_id]
    if not include_disabled:
        where += " AND disabled_at IS NULL"

    rows = await pool.fetch(
        f"""
        SELECT id, tenant_id, email::text, display_name, role,
               oidc_subject, mfa_enrolled, mfa_required,
               last_login_at, disabled_at, created_at, updated_at
          FROM tenant_users
         WHERE {where}
         ORDER BY role DESC, created_at ASC
        """,
        *args,
    )
    return [dict(r) for r in rows]


@router.get(
    "/{tenant_id}/users/{user_id}",
    response_model=TenantUser,
)
async def get_tenant_user(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant_id: UUID = Path(...),
    user_id: UUID = Path(...),
) -> dict:
    row = await pool.fetchrow(
        """
        SELECT id, tenant_id, email::text, display_name, role,
               oidc_subject, mfa_enrolled, mfa_required,
               last_login_at, disabled_at, created_at, updated_at
          FROM tenant_users
         WHERE id = $1 AND tenant_id = $2
        """,
        user_id,
        tenant_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="user not found")
    return dict(row)


@router.patch(
    "/{tenant_id}/users/{user_id}",
    response_model=TenantUser,
)
async def update_tenant_user(
    body: TenantUserUpdate,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant_id: UUID = Path(...),
    user_id: UUID = Path(...),
) -> dict:
    sets: list[str] = []
    args: list = []

    if body.display_name is not None:
        args.append(body.display_name)
        sets.append(f"display_name = ${len(args)}")
    if body.role is not None:
        args.append(body.role)
        sets.append(f"role = ${len(args)}")
        # Keep mfa_required in lockstep with role — promoting to editor
        # turns enforcement on; demoting to viewer leaves it on (don't
        # silently weaken posture).
        if body.role in ("account_owner", "editor"):
            sets.append("mfa_required = true")
    if body.oidc_subject is not None:
        args.append(body.oidc_subject)
        sets.append(f"oidc_subject = ${len(args)}")

    if not sets:
        # PATCH with empty body just returns the current row, no DB writes.
        return await get_tenant_user(pool=pool, tenant_id=tenant_id, user_id=user_id)

    args.extend([user_id, tenant_id])
    row = await pool.fetchrow(
        f"""
        UPDATE tenant_users
           SET {", ".join(sets)}
         WHERE id = ${len(args) - 1} AND tenant_id = ${len(args)}
        RETURNING id, tenant_id, email::text, display_name, role,
                  oidc_subject, mfa_enrolled, mfa_required,
                  last_login_at, disabled_at, created_at, updated_at
        """,
        *args,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="user not found")
    return dict(row)


@router.post(
    "/{tenant_id}/users/{user_id}/disable",
    response_model=TenantUser,
)
async def disable_tenant_user(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant_id: UUID = Path(...),
    user_id: UUID = Path(...),
) -> dict:
    # Account owners can't be disabled if they're the last active owner —
    # there must always be at least one. Operator can demote-then-disable
    # if they want to deactivate the only owner.
    target = await pool.fetchrow(
        "SELECT role, disabled_at FROM tenant_users WHERE id = $1 AND tenant_id = $2",
        user_id,
        tenant_id,
    )
    if target is None:
        raise HTTPException(status_code=404, detail="user not found")
    if target["disabled_at"] is not None:
        raise HTTPException(status_code=409, detail="user already disabled")

    if target["role"] == "account_owner":
        other_owners = await pool.fetchval(
            """
            SELECT COUNT(*) FROM tenant_users
             WHERE tenant_id = $1
               AND role = 'account_owner'
               AND disabled_at IS NULL
               AND id != $2
            """,
            tenant_id,
            user_id,
        )
        if other_owners == 0:
            raise HTTPException(
                status_code=409,
                detail="cannot disable the only active account_owner; "
                "demote them first or appoint another owner",
            )

    row = await pool.fetchrow(
        """
        UPDATE tenant_users
           SET disabled_at = now()
         WHERE id = $1 AND tenant_id = $2
        RETURNING id, tenant_id, email::text, display_name, role,
                  oidc_subject, mfa_enrolled, mfa_required,
                  last_login_at, disabled_at, created_at, updated_at
        """,
        user_id,
        tenant_id,
    )
    return dict(row)


@router.post(
    "/{tenant_id}/users/{user_id}/enable",
    response_model=TenantUser,
)
async def enable_tenant_user(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant_id: UUID = Path(...),
    user_id: UUID = Path(...),
) -> dict:
    row = await pool.fetchrow(
        """
        UPDATE tenant_users
           SET disabled_at = NULL
         WHERE id = $1 AND tenant_id = $2 AND disabled_at IS NOT NULL
        RETURNING id, tenant_id, email::text, display_name, role,
                  oidc_subject, mfa_enrolled, mfa_required,
                  last_login_at, disabled_at, created_at, updated_at
        """,
        user_id,
        tenant_id,
    )
    if row is None:
        # Either not found or not currently disabled.
        existing = await pool.fetchrow(
            "SELECT 1 FROM tenant_users WHERE id = $1 AND tenant_id = $2",
            user_id,
            tenant_id,
        )
        if existing is None:
            raise HTTPException(status_code=404, detail="user not found")
        raise HTTPException(status_code=409, detail="user is not disabled")
    return dict(row)


@router.post(
    "/{tenant_id}/users/{user_id}/issue-password-reset",
    response_model=PasswordResetIssued,
    status_code=201,
)
async def issue_password_reset(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant_id: UUID = Path(...),
    user_id: UUID = Path(...),
) -> PasswordResetIssued:
    """Operator-side endpoint for creating a single-use password-reset
    token. The plaintext token is returned ONCE; the operator hands it
    to the tenant user out-of-band (email, ticket comment, etc.) and
    the user redeems it at POST /portal/v1/auth/password-reset/confirm.

    Any pending (un-used) resets for the same user are silently
    invalidated — only the newest token can be redeemed."""
    target = await pool.fetchrow(
        "SELECT id FROM tenant_users WHERE id = $1 AND tenant_id = $2 AND disabled_at IS NULL",
        user_id,
        tenant_id,
    )
    if target is None:
        raise HTTPException(status_code=404, detail="user not found or disabled")

    s = get_settings()
    secret = secrets.token_urlsafe(32)  # 256 bits
    hashed = bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    expires = datetime.now(tz=timezone.utc) + timedelta(hours=s.password_reset_lifetime_hours)

    async with pool.acquire() as conn:
        async with conn.transaction():
            # Invalidate prior pending resets so the operator can't
            # accidentally hand out two live tokens.
            await conn.execute(
                """
                UPDATE tenant_user_password_resets
                   SET used_at = now()
                 WHERE tenant_user_id = $1 AND used_at IS NULL
                """,
                user_id,
            )
            row = await conn.fetchrow(
                """
                INSERT INTO tenant_user_password_resets
                    (tenant_user_id, token_hash, expires_at, issued_by_admin)
                VALUES ($1, $2, $3, true)
                RETURNING id, expires_at
                """,
                user_id,
                hashed,
                expires,
            )

    return PasswordResetIssued(
        reset_token=f"{row['id']}.{secret}",
        expires_at=row["expires_at"],
    )
