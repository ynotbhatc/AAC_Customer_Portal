"""
Operator-admin endpoints for feed runs.

GET  /api/admin/v1/feeds/runs              — recent runs across all sources
GET  /api/admin/v1/feeds/runs?source=nvd   — filtered
POST /api/admin/v1/feeds/{source}/run      — fire an adapter on demand
                                             (returns immediately; result
                                             lands in feed_runs)
GET  /api/admin/v1/feeds/cves              — recent cve_events for spot-checks
"""
from __future__ import annotations

from typing import Annotated, Literal

import asyncpg
from fastapi import APIRouter, BackgroundTasks, Depends, Path, Query

from ..core.auth import require_admin
from ..core.portal_db import get_portal_pool
from ..feeds.runner import ADAPTERS, run as run_adapter

router = APIRouter(
    prefix="/admin/v1/feeds",
    tags=["admin:feeds"],
    dependencies=[Depends(require_admin)],
)

Source = Literal["nvd", "cisa_kev"]


@router.get("/runs")
async def list_runs(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    source: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    if source:
        rows = await pool.fetch(
            """
            SELECT id, source, started_at, finished_at, status,
                   cursor_before, cursor_after,
                   rows_seen, rows_added, rows_updated,
                   http_status, error_message, metadata
              FROM feed_runs
             WHERE source = $1
             ORDER BY started_at DESC
             LIMIT $2
            """,
            source, limit,
        )
    else:
        rows = await pool.fetch(
            """
            SELECT id, source, started_at, finished_at, status,
                   cursor_before, cursor_after,
                   rows_seen, rows_added, rows_updated,
                   http_status, error_message, metadata
              FROM feed_runs
             ORDER BY started_at DESC
             LIMIT $1
            """,
            limit,
        )
    return [dict(r) for r in rows]


@router.post("/{source}/run", status_code=202)
async def trigger_run(
    source: Annotated[Source, Path()],
    background: BackgroundTasks,
    lookback_days: int = Query(default=2, ge=1, le=119),
) -> dict:
    """Fire an adapter in the background; result lands in feed_runs."""
    if source not in ADAPTERS:
        return {"status": "error", "detail": f"unknown source '{source}'"}

    async def _go() -> None:
        kwargs = {"lookback_days": lookback_days} if source == "nvd" else {}
        await run_adapter(source, **kwargs)

    background.add_task(_go)
    return {"status": "accepted", "source": source, "lookback_days": lookback_days}


@router.get("/cves")
async def list_cves(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    severity: str | None = Query(default=None, description="CRITICAL/HIGH/MEDIUM/LOW"),
    kev_only: bool = False,
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[dict]:
    conditions: list[str] = []
    args: list = []
    if severity:
        args.append(severity.upper())
        conditions.append(f"cvss_v3_severity = ${len(args)}")
    if kev_only:
        conditions.append("kev_member = true")
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    args.append(limit)
    rows = await pool.fetch(
        f"""
        SELECT cve_id, cvss_v3, cvss_v3_severity, kev_member,
               kev_date_added, vendor, product, published_at,
               last_modified_at, sources
          FROM cve_events
          {where}
         ORDER BY COALESCE(published_at, last_modified_at, received_at) DESC
         LIMIT ${len(args)}
        """,
        *args,
    )
    return [dict(r) for r in rows]
