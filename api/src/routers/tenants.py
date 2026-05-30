"""
Operator-admin endpoints for tenant + token onboarding.

All routes require the PORTAL_ADMIN_TOKEN bearer (see core/auth.py).
The customer-facing pull APIs (Piece 8) will live in a separate router
with a different auth scheme (per-tenant token).
"""
from __future__ import annotations

import secrets
import string
from typing import Annotated

import asyncpg
import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Path

from ..core.auth import require_admin
from ..core.portal_db import get_portal_pool
from ..models.tenant import (
    Tenant,
    TenantCreate,
    TenantUpdate,
    TokenCreate,
    TokenCreated,
    TokenInfo,
    TokenRevoke,
)

router = APIRouter(
    prefix="/admin/v1/tenants",
    tags=["admin:tenants"],
    dependencies=[Depends(require_admin)],
)

# ── token generation ──────────────────────────────────────────────────
TOKEN_ID_PREFIX = "aac"
TOKEN_ID_LENGTH = 16
TOKEN_SECRET_LENGTH = 48
_TOKEN_ALPHABET = string.ascii_letters + string.digits


def _new_token_id() -> str:
    body = "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(TOKEN_ID_LENGTH))
    return f"{TOKEN_ID_PREFIX}_{body}"


def _new_token_secret() -> str:
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(TOKEN_SECRET_LENGTH))


def _hash_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


# ── tenant CRUD ───────────────────────────────────────────────────────
@router.post("", response_model=Tenant, status_code=201)
async def create_tenant(
    body: TenantCreate,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    row = await pool.fetchrow(
        """
        INSERT INTO tenants
            (display_name, contact_email, tier,
             aac_bridge_url, aac_bridge_verify_ssl, notes)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        """,
        body.display_name,
        body.contact_email,
        body.tier,
        str(body.aac_bridge_url) if body.aac_bridge_url else None,
        body.aac_bridge_verify_ssl,
        body.notes,
    )
    return dict(row)


@router.get("", response_model=list[Tenant])
async def list_tenants(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    include_deleted: bool = False,
) -> list[dict]:
    if include_deleted:
        rows = await pool.fetch("SELECT * FROM tenants ORDER BY created_at DESC")
    else:
        rows = await pool.fetch(
            "SELECT * FROM tenants WHERE status != 'deleted' ORDER BY created_at DESC"
        )
    return [dict(r) for r in rows]


@router.get("/{tenant_id}", response_model=Tenant)
async def get_tenant(
    tenant_id: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    row = await pool.fetchrow("SELECT * FROM tenants WHERE id = $1::uuid", tenant_id)
    if row is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    return dict(row)


@router.patch("/{tenant_id}", response_model=Tenant)
async def update_tenant(
    tenant_id: Annotated[str, Path()],
    body: TenantUpdate,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    fields = body.model_dump(exclude_none=True)
    if not fields:
        raise HTTPException(status_code=400, detail="no fields to update")

    if "aac_bridge_url" in fields and fields["aac_bridge_url"] is not None:
        fields["aac_bridge_url"] = str(fields["aac_bridge_url"])

    set_clauses = []
    args: list = []
    for i, (k, v) in enumerate(fields.items(), start=1):
        set_clauses.append(f"{k} = ${i}")
        args.append(v)
    args.append(tenant_id)

    row = await pool.fetchrow(
        f"""
        UPDATE tenants
           SET {', '.join(set_clauses)}
         WHERE id = ${len(args)}::uuid
        RETURNING *
        """,
        *args,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="tenant not found")
    return dict(row)


@router.delete("/{tenant_id}", status_code=204)
async def soft_delete_tenant(
    tenant_id: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> None:
    result = await pool.execute(
        "UPDATE tenants SET status = 'deleted' WHERE id = $1::uuid",
        tenant_id,
    )
    if result.endswith(" 0"):
        raise HTTPException(status_code=404, detail="tenant not found")


# ── token management ──────────────────────────────────────────────────
@router.post("/{tenant_id}/tokens", response_model=TokenCreated, status_code=201)
async def create_token(
    tenant_id: Annotated[str, Path()],
    body: TokenCreate,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    tenant = await pool.fetchrow("SELECT id FROM tenants WHERE id = $1::uuid", tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="tenant not found")

    token_id = _new_token_id()
    token_secret = _new_token_secret()
    secret_hash = _hash_secret(token_secret)

    row = await pool.fetchrow(
        """
        INSERT INTO tenant_tokens
            (tenant_id, token_id, token_secret_hash, description, scopes)
        VALUES ($1::uuid, $2, $3, $4, $5)
        RETURNING id, tenant_id, token_id, description, scopes,
                  created_at, created_by, last_used_at,
                  revoked_at, revoked_reason
        """,
        tenant_id,
        token_id,
        secret_hash,
        body.description,
        body.scopes,
    )
    return {**dict(row), "token_secret": token_secret}


@router.get("/{tenant_id}/tokens", response_model=list[TokenInfo])
async def list_tokens(
    tenant_id: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    include_revoked: bool = False,
) -> list[dict]:
    if include_revoked:
        rows = await pool.fetch(
            """
            SELECT id, tenant_id, token_id, description, scopes,
                   created_at, created_by, last_used_at,
                   revoked_at, revoked_reason
              FROM tenant_tokens
             WHERE tenant_id = $1::uuid
             ORDER BY created_at DESC
            """,
            tenant_id,
        )
    else:
        rows = await pool.fetch(
            """
            SELECT id, tenant_id, token_id, description, scopes,
                   created_at, created_by, last_used_at,
                   revoked_at, revoked_reason
              FROM tenant_tokens
             WHERE tenant_id = $1::uuid AND revoked_at IS NULL
             ORDER BY created_at DESC
            """,
            tenant_id,
        )
    return [dict(r) for r in rows]


@router.post("/{tenant_id}/tokens/{token_id}/revoke", status_code=204)
async def revoke_token(
    tenant_id: Annotated[str, Path()],
    token_id: Annotated[str, Path()],
    body: TokenRevoke,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> None:
    result = await pool.execute(
        """
        UPDATE tenant_tokens
           SET revoked_at = now(),
               revoked_reason = $1
         WHERE tenant_id = $2::uuid
           AND token_id = $3
           AND revoked_at IS NULL
        """,
        body.reason,
        tenant_id,
        token_id,
    )
    if result.endswith(" 0"):
        raise HTTPException(status_code=404, detail="active token not found")
