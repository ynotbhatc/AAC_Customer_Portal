"""Baseline snapshot endpoints (Piece 50).

Three surfaces:

  Bridge / M2M (scope=baseline_push)
      POST /api/portal/v1/tenants/{tenant_id}/baselines
          Ingest a fresh evaluation result from the bridge. Server
          stamps source='bridge_push' so the audit trail is honest.

  Tenant user (MFA session)
      GET  /api/portal/v1/me/baselines           — list (cursor-paginated)
      GET  /api/portal/v1/me/baselines/{id}      — full detail incl. summary jsonb
      POST /api/portal/v1/me/baselines           — manual import (operator UX
                                                   for backfills + testing)

`bundle_bytes` / `signed_envelope_bytes` are NOT involved here —
baselines are about evaluation results, not the bundle itself. The
bundle_sha256 is just a foreign-key-ish pointer for "what was OPA
running when this ran."
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Path, Query

from ..core.portal_db import get_portal_pool
from ..core.sessions import require_tenant_user_mfa
from ..core.tenant_auth import BASELINE_PUSH_SCOPE, require_tenant_with_scope
from ..models.baseline import (
    BaselineIngestRequest,
    BaselineSnapshotDetail,
    BaselineSnapshotSummary,
)


# ── User-facing list + detail + manual import ─────────────────────────


user_router = APIRouter(
    prefix="/portal/v1/me/baselines",
    tags=["portal:baselines"],
)


def _ensure_json(value: Any) -> Any:
    """asyncpg returns jsonb as raw JSON-text str unless a connection
    codec is registered. Same defensive parse pattern used elsewhere
    in this codebase for ir_json / manifest / details."""
    return json.loads(value) if isinstance(value, str) else value


def _summary_to_summary_row(row: dict) -> dict:
    """Project the lean summary fields the list view needs from the
    `summary` jsonb so the BaselineSnapshotSummary model gets
    flat values."""
    s = _ensure_json(row["summary"])
    return {
        "id": row["id"],
        "tenant_id": row["tenant_id"],
        "bundle_sha256": row["bundle_sha256"],
        "captured_at": row["captured_at"],
        "captured_by_email": row.get("captured_by_email"),
        "label": row["label"],
        "source": row["source"],
        "host_count": int(s.get("host_count", 0)),
        "passing": int(s.get("passing", 0)),
        "failing": int(s.get("failing", 0)),
    }


@user_router.get("", response_model=list[BaselineSnapshotSummary])
async def list_baselines(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    limit: int = Query(50, ge=1, le=200),
    before_captured_at: datetime | None = Query(
        None,
        description="Cursor — pass with before_id (both or neither). "
        "Returns entries strictly before this (captured_at, id) pair.",
    ),
    before_id: UUID | None = Query(
        None,
        description="Tiebreaker for before_captured_at. The id of the "
        "oldest entry from the prior page.",
    ),
) -> list[dict[str, Any]]:
    """Reverse-chronological baseline history for the tenant.

    Cursor-paired on (captured_at, id) for the same reason
    list_bundle_history is — two captures CAN land in the same
    microsecond on a busy bridge; without the id tiebreaker the
    duplicate would appear on two pages.
    """
    if (before_captured_at is None) != (before_id is None):
        raise HTTPException(
            status_code=400,
            detail="before_captured_at and before_id must be passed together",
        )

    base_select = """
        SELECT bs.id, bs.tenant_id, bs.bundle_sha256, bs.captured_at,
               bs.label, bs.source, bs.summary,
               tu.email AS captured_by_email
          FROM baseline_snapshots bs
          LEFT JOIN tenant_users tu ON tu.id = bs.captured_by_user_id
         WHERE bs.tenant_id = $1
    """
    if before_captured_at is None:
        rows = await pool.fetch(
            base_select
            + " ORDER BY bs.captured_at DESC, bs.id DESC LIMIT $2",
            tenant_user["tenant_id"],
            limit,
        )
    else:
        rows = await pool.fetch(
            base_select
            + " AND (bs.captured_at, bs.id) < ($2, $3)"
            + " ORDER BY bs.captured_at DESC, bs.id DESC LIMIT $4",
            tenant_user["tenant_id"],
            before_captured_at,
            before_id,
            limit,
        )

    return [_summary_to_summary_row(dict(r)) for r in rows]


@user_router.get("/{baseline_id}", response_model=BaselineSnapshotDetail)
async def get_baseline(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    baseline_id: UUID = Path(...),
) -> dict[str, Any]:
    """Single baseline with the full summary jsonb.

    Tenant-scoped via the WHERE clause: a baseline id owned by
    another tenant 404s identically to a non-existent id, so we
    don't leak existence across tenants.
    """
    row = await pool.fetchrow(
        """
        SELECT bs.id, bs.tenant_id, bs.bundle_sha256, bs.captured_at,
               bs.label, bs.source, bs.summary,
               tu.email AS captured_by_email
          FROM baseline_snapshots bs
          LEFT JOIN tenant_users tu ON tu.id = bs.captured_by_user_id
         WHERE bs.id = $1 AND bs.tenant_id = $2
        """,
        baseline_id,
        tenant_user["tenant_id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="baseline not found")
    base = _summary_to_summary_row(dict(row))
    return {**base, "summary": _ensure_json(row["summary"])}


@user_router.post(
    "",
    response_model=BaselineSnapshotDetail,
    status_code=201,
)
async def manual_import_baseline(
    body: BaselineIngestRequest,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict[str, Any]:
    """Operator/customer UX path: paste a baseline JSON to import it.

    Useful for backfilling historical evaluations + for testing the
    storage path without standing up a bridge. Server stamps
    source='manual' regardless of body.
    """
    row = await pool.fetchrow(
        """
        INSERT INTO baseline_snapshots
            (tenant_id, bundle_sha256, captured_by_user_id, label,
             summary, source)
        VALUES ($1, $2, $3, $4, $5::jsonb, 'manual')
        RETURNING id, tenant_id, bundle_sha256, captured_at, label,
                  source, summary
        """,
        tenant_user["tenant_id"],
        body.bundle_sha256,
        tenant_user["tenant_user_id"],
        body.label,
        body.summary.model_dump_json(),
    )
    # Re-fetch with the email join so the response shape matches the
    # GET endpoint exactly.
    actor_email = await pool.fetchval(
        "SELECT email FROM tenant_users WHERE id = $1",
        tenant_user["tenant_user_id"],
    )
    base = _summary_to_summary_row(
        {**dict(row), "captured_by_email": actor_email}
    )
    return {**base, "summary": _ensure_json(row["summary"])}


# ── Bridge / M2M ingest ───────────────────────────────────────────────


bridge_router = APIRouter(
    prefix="/portal/v1/tenants/{tenant_id}/baselines",
    tags=["bridge:baselines"],
)

_bridge_dep = require_tenant_with_scope(BASELINE_PUSH_SCOPE)


@bridge_router.post("", status_code=201)
async def ingest_baseline(
    body: BaselineIngestRequest,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant: Annotated[dict[str, Any], Depends(_bridge_dep)],
    tenant_id: UUID = Path(...),
) -> dict[str, str]:
    """Bridge posts a fresh evaluation result.

    Returns just the id — the bridge doesn't typically need the
    rest, and keeping the response minimal saves a JOIN to
    tenant_users that wouldn't apply to a bridge-originated row
    anyway (captured_by_user_id is NULL on this path).
    """
    if tenant["tenant_id"] != tenant_id:
        # require_tenant_with_scope already validated the token, but
        # mismatched path-tenant vs token-tenant is a clear 403.
        raise HTTPException(
            status_code=403,
            detail="token does not match the tenant in the URL",
        )
    row = await pool.fetchrow(
        """
        INSERT INTO baseline_snapshots
            (tenant_id, bundle_sha256, label, summary, source)
        VALUES ($1, $2, $3, $4::jsonb, 'bridge_push')
        RETURNING id
        """,
        tenant_id,
        body.bundle_sha256,
        body.label,
        body.summary.model_dump_json(),
    )
    return {"id": str(row["id"])}
