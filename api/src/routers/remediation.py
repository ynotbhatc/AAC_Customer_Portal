"""Remediation router — real implementation (P0-C).

State machine
=============

    open ──assign──> in_progress ──submit──> pending_approval
                          ▲                       │
                          │                       ├──approve──> approved
                          │                       │
                          └─reject (audited)──────┘

Four-eyes invariant
===================

The actor who calls POST /{id}/approve MUST be different from the
actor who called POST /{id}/submit. The DB CHECK constraint
`four_eyes_separate_actors` (migration 016) enforces this at the
storage layer so a router bug can't silently bypass it.

Audit
=====

Every transition writes to two trails:

- system_audit_log (auto, via AuditMiddleware) — security across
  the whole API
- remediation_history (this router) — compliance-officer-friendly
  per-item timeline

Tenant scoping
==============

Every read filters by `tenant_id = $tenant`. The four-eyes table is
tenant-owned so no cross-tenant leak path through this surface.
"""
from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from ..core.portal_db import get_portal_pool
from ..core.rbac import require_role
from ..core.sessions import require_tenant_user, require_tenant_user_mfa

# All reads require a logged-in user. State-change endpoints
# additionally require an MFA-verified session — see per-route
# `dependencies=[Depends(require_tenant_user_mfa)]`.
router = APIRouter(
    prefix="/remediation",
    tags=["remediation"],
    dependencies=[Depends(require_tenant_user)],
)


# ── Models ───────────────────────────────────────────────────────────


class RemediationItem(BaseModel):
    id: UUID
    tenant_id: UUID
    hostname: str
    framework: str
    control_id: str
    description: str
    severity: Literal["critical", "high", "medium", "low"]
    status: Literal["open", "in_progress", "pending_approval", "approved"]
    assigned_to: UUID | None = None
    requested_approval_at: Any = None
    requested_approval_by: UUID | None = None
    approved_at: Any = None
    approved_by: UUID | None = None
    approval_notes: str | None = None
    created_at: Any
    updated_at: Any


class HistoryEntry(BaseModel):
    transition: Literal["create", "assign", "submit", "approve", "reject"]
    from_status: str | None = None
    to_status: str
    actor_id: UUID | None = None
    notes: str | None = None
    at: Any


class CreateItem(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    framework: str = Field(..., min_length=1, max_length=100)
    control_id: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=2000)
    severity: Literal["critical", "high", "medium", "low"]


class AssignItem(BaseModel):
    assigned_to: UUID


class SubmitItem(BaseModel):
    notes: str | None = Field(None, max_length=2000)


class ApproveItem(BaseModel):
    notes: str | None = Field(None, max_length=2000)


class RejectItem(BaseModel):
    notes: str = Field(..., min_length=1, max_length=2000, description="rejection requires a reason")


# ── Helpers ──────────────────────────────────────────────────────────


async def _record_history(
    conn: asyncpg.Connection,
    *,
    item_id: UUID,
    actor_id: UUID,
    transition: str,
    from_status: str | None,
    to_status: str,
    notes: str | None,
) -> None:
    await conn.execute(
        """
        INSERT INTO remediation_history
            (item_id, actor_id, transition, from_status, to_status, notes)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        item_id,
        actor_id,
        transition,
        from_status,
        to_status,
        notes,
    )


async def _load_item(
    pool: asyncpg.Pool,
    item_id: UUID,
    tenant_id: UUID,
) -> dict[str, Any]:
    """Load a tenant-owned item or 404 — for read-only paths only.

    Writers MUST use `_load_item_for_update` (below) inside their
    transaction connection so the row stays locked between the
    status check and the UPDATE. This helper opens its own
    connection from the pool and is therefore unsafe for
    state-machine transitions — two concurrent transitions could
    both see the same pre-state and both proceed."""
    row = await pool.fetchrow(
        """
        SELECT * FROM remediation_items
         WHERE id = $1 AND tenant_id = $2
        """,
        item_id,
        tenant_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="remediation item not found")
    return dict(row)


async def _load_item_for_update(
    conn: asyncpg.Connection,
    item_id: UUID,
    tenant_id: UUID,
) -> dict[str, Any]:
    """Load + lock a tenant-owned item on the SAME connection.

    Must be called inside `async with conn.transaction():`. The
    `FOR UPDATE` clause holds the row lock until the transaction
    commits, so a concurrent transition trying to mutate the same
    row blocks until we're done. This makes the
    state-check-then-UPDATE pair atomic — without it, two clients
    could both observe `open` and both try to assign, producing
    inconsistent history rows."""
    row = await conn.fetchrow(
        """
        SELECT * FROM remediation_items
         WHERE id = $1 AND tenant_id = $2
         FOR UPDATE
        """,
        item_id,
        tenant_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="remediation item not found")
    return dict(row)


def _tag_resource(request: Request, item_id: UUID | str) -> None:
    """Attach (resource_type, resource_id) for the AuditMiddleware."""
    request.state.audit_resource = ("remediation_item", str(item_id))


# ── Routes ───────────────────────────────────────────────────────────


@router.get("", response_model=list[RemediationItem])
async def list_items(
    user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    hostname: str | None = None,
    # The query parameter is named `status` (matches the frontend
    # client). The local variable is `status_filter` because `status`
    # collides with the imported starlette status module. Without the
    # `alias`, `?status=...` was silently ignored — caller had to send
    # `?status_filter=...` to filter, which nothing did.
    status_filter: Annotated[
        Literal["open", "in_progress", "pending_approval", "approved"] | None,
        Query(alias="status"),
    ] = None,
    severity: Literal["critical", "high", "medium", "low"] | None = None,
    # Clamp to [1, 500]. Without the lower bound, `?limit=-1` is a
    # caller-controlled DoS: Postgres treats `LIMIT -1` as "no
    # limit" and the whole table comes back over the wire.
    limit: int = Query(default=100, ge=1, le=500),
):
    """List remediation items for the current tenant, optionally
    filtered by hostname / status / severity."""
    conditions = ["tenant_id = $1"]
    args: list[Any] = [user["tenant_id"]]
    if hostname:
        args.append(hostname)
        conditions.append(f"hostname = ${len(args)}")
    if status_filter:
        args.append(status_filter)
        conditions.append(f"status = ${len(args)}")
    if severity:
        args.append(severity)
        conditions.append(f"severity = ${len(args)}")
    args.append(limit)

    rows = await pool.fetch(
        f"""
        SELECT * FROM remediation_items
         WHERE {" AND ".join(conditions)}
         ORDER BY created_at DESC
         LIMIT ${len(args)}
        """,
        *args,
    )
    return [dict(r) for r in rows]


@router.get("/{item_id}", response_model=RemediationItem)
async def get_item(
    item_id: UUID,
    user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
):
    return await _load_item(pool, item_id, user["tenant_id"])


@router.get("/{item_id}/history", response_model=list[HistoryEntry])
async def get_history(
    item_id: UUID,
    user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
):
    # Tenant check: only return history if the item belongs to this tenant
    await _load_item(pool, item_id, user["tenant_id"])
    rows = await pool.fetch(
        """
        SELECT transition, from_status, to_status, actor_id, notes, at
          FROM remediation_history
         WHERE item_id = $1
         ORDER BY at ASC
        """,
        item_id,
    )
    return [dict(r) for r in rows]


@router.post(
    "",
    response_model=RemediationItem,
    status_code=201,
    dependencies=[Depends(require_tenant_user_mfa), Depends(require_role("editor"))],
)
async def create_item(
    body: CreateItem,
    request: Request,
    user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
):
    """Create a new remediation item in `open` state."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                INSERT INTO remediation_items
                    (tenant_id, hostname, framework, control_id,
                     description, severity, status, created_by, updated_by)
                VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $7)
                RETURNING *
                """,
                user["tenant_id"],
                body.hostname,
                body.framework,
                body.control_id,
                body.description,
                body.severity,
                user["tenant_user_id"],
            )
            await _record_history(
                conn,
                item_id=row["id"],
                actor_id=user["tenant_user_id"],
                transition="create",
                from_status=None,
                to_status="open",
                notes=None,
            )
    _tag_resource(request, row["id"])
    return dict(row)


@router.post(
    "/{item_id}/assign",
    response_model=RemediationItem,
    dependencies=[Depends(require_tenant_user_mfa), Depends(require_role("editor"))],
)
async def assign_item(
    item_id: UUID,
    body: AssignItem,
    request: Request,
    user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
):
    """`open` → `in_progress`. Assignee must be a tenant_user in the
    same tenant (FK ensures the user exists; the cross-tenant check
    is below)."""
    _tag_resource(request, item_id)
    async with pool.acquire() as conn:
        async with conn.transaction():
            current = await _load_item_for_update(conn, item_id, user["tenant_id"])
            if current["status"] != "open":
                raise HTTPException(
                    status_code=409,
                    detail=f"item is in status {current['status']!r}; assign only valid from 'open'",
                )
            # Cross-tenant assignee check
            assignee_tenant = await conn.fetchval(
                "SELECT tenant_id FROM tenant_users WHERE id = $1",
                body.assigned_to,
            )
            if assignee_tenant != user["tenant_id"]:
                raise HTTPException(
                    status_code=400,
                    detail="assigned_to user does not exist or belongs to a different tenant",
                )
            row = await conn.fetchrow(
                """
                UPDATE remediation_items
                   SET status = 'in_progress',
                       assigned_to = $1,
                       updated_at = now(),
                       updated_by = $2
                 WHERE id = $3 AND tenant_id = $4
                 RETURNING *
                """,
                body.assigned_to,
                user["tenant_user_id"],
                item_id,
                user["tenant_id"],
            )
            await _record_history(
                conn,
                item_id=item_id,
                actor_id=user["tenant_user_id"],
                transition="assign",
                from_status="open",
                to_status="in_progress",
                notes=None,
            )
    return dict(row)


@router.post(
    "/{item_id}/submit",
    response_model=RemediationItem,
    dependencies=[Depends(require_tenant_user_mfa), Depends(require_role("editor"))],
)
async def submit_item(
    item_id: UUID,
    body: SubmitItem,
    request: Request,
    user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
):
    """`in_progress` → `pending_approval`. Records who requested
    approval so the four-eyes invariant can reject same-actor
    approval on the next step."""
    _tag_resource(request, item_id)
    async with pool.acquire() as conn:
        async with conn.transaction():
            current = await _load_item_for_update(conn, item_id, user["tenant_id"])
            if current["status"] != "in_progress":
                raise HTTPException(
                    status_code=409,
                    detail=f"item is in status {current['status']!r}; submit only valid from 'in_progress'",
                )
            row = await conn.fetchrow(
                """
                UPDATE remediation_items
                   SET status = 'pending_approval',
                       requested_approval_at = now(),
                       requested_approval_by = $1,
                       updated_at = now(),
                       updated_by = $1
                 WHERE id = $2 AND tenant_id = $3
                 RETURNING *
                """,
                user["tenant_user_id"],
                item_id,
                user["tenant_id"],
            )
            await _record_history(
                conn,
                item_id=item_id,
                actor_id=user["tenant_user_id"],
                transition="submit",
                from_status="in_progress",
                to_status="pending_approval",
                notes=body.notes,
            )
    return dict(row)


@router.post(
    "/{item_id}/approve",
    response_model=RemediationItem,
    dependencies=[Depends(require_tenant_user_mfa), Depends(require_role("editor"))],
)
async def approve_item(
    item_id: UUID,
    body: ApproveItem,
    request: Request,
    user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
):
    """`pending_approval` → `approved`. Four-eyes: caller must NOT be
    the requester. Enforced at the router AND at the DB (CHECK
    constraint on migration 016)."""
    _tag_resource(request, item_id)
    async with pool.acquire() as conn:
        async with conn.transaction():
            current = await _load_item_for_update(conn, item_id, user["tenant_id"])
            if current["status"] != "pending_approval":
                raise HTTPException(
                    status_code=409,
                    detail=f"item is in status {current['status']!r}; approve only valid from 'pending_approval'",
                )
            if current.get("requested_approval_by") == user["tenant_user_id"]:
                raise HTTPException(
                    status_code=403,
                    detail="four-eyes: the user who submitted for approval cannot approve",
                )
            row = await conn.fetchrow(
                """
                UPDATE remediation_items
                   SET status = 'approved',
                       approved_at = now(),
                       approved_by = $1,
                       approval_notes = $2,
                       updated_at = now(),
                       updated_by = $1
                 WHERE id = $3 AND tenant_id = $4
                 RETURNING *
                """,
                user["tenant_user_id"],
                body.notes,
                item_id,
                user["tenant_id"],
            )
            await _record_history(
                conn,
                item_id=item_id,
                actor_id=user["tenant_user_id"],
                transition="approve",
                from_status="pending_approval",
                to_status="approved",
                notes=body.notes,
            )
    return dict(row)


@router.post(
    "/{item_id}/reject",
    response_model=RemediationItem,
    dependencies=[Depends(require_tenant_user_mfa), Depends(require_role("editor"))],
)
async def reject_item(
    item_id: UUID,
    body: RejectItem,
    request: Request,
    user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
):
    """`pending_approval` → `in_progress`. Rejection requires a
    reason (model enforces non-empty notes). Also subject to the
    four-eyes rule: the requester can't reject their own submission
    — they'd just retract instead, but that's not modeled today."""
    _tag_resource(request, item_id)
    async with pool.acquire() as conn:
        async with conn.transaction():
            current = await _load_item_for_update(conn, item_id, user["tenant_id"])
            if current["status"] != "pending_approval":
                raise HTTPException(
                    status_code=409,
                    detail=f"item is in status {current['status']!r}; reject only valid from 'pending_approval'",
                )
            if current.get("requested_approval_by") == user["tenant_user_id"]:
                raise HTTPException(
                    status_code=403,
                    detail="four-eyes: the user who submitted for approval cannot reject",
                )
            row = await conn.fetchrow(
                """
                UPDATE remediation_items
                   SET status = 'in_progress',
                       requested_approval_at = NULL,
                       requested_approval_by = NULL,
                       updated_at = now(),
                       updated_by = $1
                 WHERE id = $2 AND tenant_id = $3
                 RETURNING *
                """,
                user["tenant_user_id"],
                item_id,
                user["tenant_id"],
            )
            await _record_history(
                conn,
                item_id=item_id,
                actor_id=user["tenant_user_id"],
                transition="reject",
                from_status="pending_approval",
                to_status="in_progress",
                notes=body.notes,
            )
    return dict(row)
