"""Tenant-admin endpoints for managing `tenant_host_mapping` rows
(P0-A3). The mapping table (migration 015) drives multi-tenant
read-scoping for compliance routes; a tenant admin needs a way to
add/remove rows without operator intervention.

Endpoints (all under `/portal/v1/me/host-mappings`):

  GET    /                   list this tenant's mappings
  POST   /                   add a (hostname, optional framework) mapping
  DELETE /{mapping_id}       remove a single mapping

Authorization:
  - require_role("account_owner") — tenant admins only. Editors and
    viewers can see compliance data (subject to existing mappings)
    but only the owner can change who-sees-what.
  - All endpoints additionally require MFA-verified session (writes
    of this class are the four-eyes / accountability tier).

Audit:
  - AuditMiddleware (#47/#50) auto-logs every write to
    system_audit_log. We tag request.state.audit_resource so the
    resource columns carry mapping_id when present.
"""
from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..core.portal_db import get_portal_pool
from ..core.rbac import require_role
from ..core.sessions import require_tenant_user_mfa


router = APIRouter(
    prefix="/portal/v1/me/host-mappings",
    tags=["portal:host-mappings"],
    dependencies=[
        Depends(require_tenant_user_mfa),
        Depends(require_role("account_owner")),
    ],
)


# ── Models ───────────────────────────────────────────────────────────


class HostMapping(BaseModel):
    id: UUID
    tenant_id: UUID
    hostname: str
    framework: str | None = None
    created_at: Any
    created_by: UUID | None = None


class CreateMapping(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    framework: str | None = Field(None, max_length=100)


# ── Routes ───────────────────────────────────────────────────────────


@router.get("", response_model=list[HostMapping])
async def list_mappings(
    user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
):
    rows = await pool.fetch(
        """
        SELECT id, tenant_id, hostname, framework, created_at, created_by
          FROM tenant_host_mapping
         WHERE tenant_id = $1
         ORDER BY hostname ASC, framework ASC NULLS FIRST
        """,
        user["tenant_id"],
    )
    return [dict(r) for r in rows]


@router.post("", response_model=HostMapping, status_code=201)
async def create_mapping(
    body: CreateMapping,
    request: Request,
    user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
):
    """Add a (hostname [, framework]) mapping for the current tenant.

    Returns 409 if the exact triple already exists. The
    `uniq_tenant_host_framework` unique index folds NULL framework
    and same string into one bucket — see migration 015.
    """
    try:
        row = await pool.fetchrow(
            """
            INSERT INTO tenant_host_mapping
                (tenant_id, hostname, framework, created_by)
            VALUES ($1, $2, $3, $4)
            RETURNING id, tenant_id, hostname, framework, created_at, created_by
            """,
            user["tenant_id"],
            body.hostname,
            body.framework,
            user["tenant_user_id"],
        )
    except asyncpg.UniqueViolationError:
        raise HTTPException(
            status_code=409,
            detail=(
                f"mapping for hostname={body.hostname!r} "
                f"framework={body.framework!r} already exists"
            ),
        )
    request.state.audit_resource = ("tenant_host_mapping", str(row["id"]))
    return dict(row)


@router.delete("/{mapping_id}", status_code=204)
async def delete_mapping(
    mapping_id: UUID,
    request: Request,
    user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
):
    """Remove a single mapping. 404 if it doesn't exist or belongs to
    another tenant (no existence leak)."""
    request.state.audit_resource = ("tenant_host_mapping", str(mapping_id))
    deleted = await pool.fetchval(
        """
        DELETE FROM tenant_host_mapping
         WHERE id = $1 AND tenant_id = $2
         RETURNING id
        """,
        mapping_id,
        user["tenant_id"],
    )
    if deleted is None:
        raise HTTPException(status_code=404, detail="mapping not found")
    return None
