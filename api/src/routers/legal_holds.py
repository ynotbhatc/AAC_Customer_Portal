"""Operator-admin endpoints for applying and releasing legal holds.

Wraps the SQL flow documented in `docs/runbooks/legal_hold.md` in a
typed API. The DB-level mechanism (migration 018) is the source of
truth for what mutations are allowed once a hold is set; this router
is the ergonomic interface that operators reach for first.

All routes require `PORTAL_ADMIN_TOKEN`. The AuditMiddleware writes
a `system_audit_log` row for every mutation; per-route logic adds
`request.state.audit_extra` so the approval/release ticket and reason
are captured in `details`.

API surface:
  POST   /admin/v1/legal-holds                    apply a hold
  DELETE /admin/v1/legal-holds/{type}/{row_id}    release a hold
  GET    /admin/v1/legal-holds                    enumerate held rows

`type` is a literal — only `policy_audit_log` and `baseline_snapshots`
are accepted. The path / body values are mapped to fully-qualified
table names internally; the operator never types raw SQL.
"""
from __future__ import annotations

from typing import Annotated
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response

from ..core.auth import require_admin
from ..core.portal_db import get_portal_pool
from ..models.legal_hold import (
    LegalHoldApply,
    LegalHoldEntry,
    LegalHoldRelease,
    LegalHoldTable,
)


router = APIRouter(
    prefix="/admin/v1/legal-holds",
    tags=["admin:legal-holds"],
    dependencies=[Depends(require_admin)],
)


# ── Helpers ──────────────────────────────────────────────────────────


def _validate_id(resource_type: LegalHoldTable, raw: str) -> int | UUID:
    """Coerce the path/body row id to the type the table expects."""
    if resource_type == "policy_audit_log":
        try:
            return int(raw)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="policy_audit_log.id must be an integer",
            ) from exc
    # baseline_snapshots
    try:
        return UUID(raw)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="baseline_snapshots.id must be a UUID",
        ) from exc


def _audit_resource_for(resource_type: LegalHoldTable) -> str:
    """The system_audit_log `resource_type` value for a legal-hold
    operation. Auditors filter on this to enumerate every hold
    apply/release across time."""
    return f"legal_hold:{resource_type}"


# ── Apply ────────────────────────────────────────────────────────────


@router.post("", status_code=201, response_model=LegalHoldEntry)
async def apply_legal_hold(
    request: Request,
    body: LegalHoldApply,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> LegalHoldEntry:
    """Apply a legal hold to one row.

    Conflict semantics: if the row already has a non-NULL
    `legal_hold_reason`, this 409s. To change a hold's reason,
    release it via DELETE and re-apply via a fresh POST — the two
    intentions then show up as separate events in the audit log.
    """
    row_id = _validate_id(body.resource_type, body.resource_id)

    if body.resource_type == "policy_audit_log":
        query_check = "SELECT tenant_id, legal_hold_reason FROM policy_audit_log WHERE id = $1"
        query_apply = (
            "UPDATE policy_audit_log SET legal_hold_reason = $1 "
            "WHERE id = $2 AND legal_hold_reason IS NULL"
        )
    else:
        query_check = "SELECT tenant_id, legal_hold_reason FROM baseline_snapshots WHERE id = $1"
        query_apply = (
            "UPDATE baseline_snapshots SET legal_hold_reason = $1 "
            "WHERE id = $2 AND legal_hold_reason IS NULL"
        )

    async with pool.acquire() as conn:
        async with conn.transaction():
            existing = await conn.fetchrow(query_check, row_id)
            if existing is None:
                raise HTTPException(status_code=404, detail="row not found")
            if existing["legal_hold_reason"] is not None:
                raise HTTPException(
                    status_code=409,
                    detail="row is already on legal hold (release before reapplying)",
                )
            result = await conn.execute(query_apply, body.reason, row_id)
            # asyncpg.execute returns "UPDATE N" — defensive verification
            # that the row was actually flipped (catches the unlikely
            # race where another caller applied a hold between the
            # SELECT and the UPDATE).
            if not result.endswith(" 1"):
                raise HTTPException(
                    status_code=409,
                    detail="row was concurrently held; retry",
                )

    request.state.audit_resource = (_audit_resource_for(body.resource_type), body.resource_id)
    request.state.audit_extra = {
        "approval_ticket": body.approval_ticket,
        "reason": body.reason,
        "tenant_id": str(existing["tenant_id"]),
    }
    return LegalHoldEntry(
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        reason=body.reason,
        tenant_id=str(existing["tenant_id"]),
    )


# ── Release ──────────────────────────────────────────────────────────


@router.delete(
    "/{resource_type}/{resource_id}",
    status_code=204,
    response_class=Response,
    response_model=None,
)
async def release_legal_hold(
    request: Request,
    resource_type: Annotated[LegalHoldTable, Path()],
    resource_id: Annotated[str, Path()],
    body: LegalHoldRelease,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> None:
    """Release a legal hold from one row.

    404 if the row doesn't exist. 409 if the row exists but isn't on
    hold — releasing something that wasn't held is almost always a
    pointer error, and silently no-op'ing would obscure it.
    """
    row_id = _validate_id(resource_type, resource_id)

    if resource_type == "policy_audit_log":
        query_check = "SELECT tenant_id, legal_hold_reason FROM policy_audit_log WHERE id = $1"
        query_release = (
            "UPDATE policy_audit_log SET legal_hold_reason = NULL "
            "WHERE id = $1 AND legal_hold_reason IS NOT NULL"
        )
    else:
        query_check = "SELECT tenant_id, legal_hold_reason FROM baseline_snapshots WHERE id = $1"
        query_release = (
            "UPDATE baseline_snapshots SET legal_hold_reason = NULL "
            "WHERE id = $1 AND legal_hold_reason IS NOT NULL"
        )

    async with pool.acquire() as conn:
        async with conn.transaction():
            existing = await conn.fetchrow(query_check, row_id)
            if existing is None:
                raise HTTPException(status_code=404, detail="row not found")
            if existing["legal_hold_reason"] is None:
                raise HTTPException(
                    status_code=409,
                    detail="row is not on legal hold (nothing to release)",
                )
            result = await conn.execute(query_release, row_id)
            if not result.endswith(" 1"):
                raise HTTPException(
                    status_code=409,
                    detail="row was concurrently released; retry",
                )

    request.state.audit_resource = (_audit_resource_for(resource_type), resource_id)
    request.state.audit_extra = {
        "release_ticket": body.release_ticket,
        "prior_reason": existing["legal_hold_reason"],
        "tenant_id": str(existing["tenant_id"]),
    }


# ── List ─────────────────────────────────────────────────────────────


@router.get("", response_model=list[LegalHoldEntry])
async def list_legal_holds(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> list[LegalHoldEntry]:
    """Enumerate every row currently on legal hold across both
    supported tables. Reads are backed by the partial indexes added
    in migration 018, so the cost is `O(# held rows)` not the full
    audit-table size.
    """
    rows = await pool.fetch(
        """
        SELECT 'policy_audit_log' AS resource_type,
               id::text             AS resource_id,
               legal_hold_reason    AS reason,
               tenant_id::text      AS tenant_id
          FROM policy_audit_log
         WHERE legal_hold_reason IS NOT NULL
        UNION ALL
        SELECT 'baseline_snapshots' AS resource_type,
               id::text             AS resource_id,
               legal_hold_reason    AS reason,
               tenant_id::text      AS tenant_id
          FROM baseline_snapshots
         WHERE legal_hold_reason IS NOT NULL
        """,
    )
    return [LegalHoldEntry(**dict(r)) for r in rows]
