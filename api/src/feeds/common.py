"""Shared helpers for feed adapters: run lifecycle, severity mapping."""
from __future__ import annotations

import asyncpg
from datetime import datetime, timezone


async def open_run(
    pool: asyncpg.Pool,
    source: str,
    cursor_before: datetime | None,
) -> int:
    row = await pool.fetchrow(
        """
        INSERT INTO feed_runs (source, cursor_before, status)
        VALUES ($1, $2, 'running')
        RETURNING id
        """,
        source,
        cursor_before,
    )
    return row["id"]


async def close_run(
    pool: asyncpg.Pool,
    run_id: int,
    *,
    status: str,
    cursor_after: datetime | None = None,
    rows_seen: int = 0,
    rows_added: int = 0,
    rows_updated: int = 0,
    http_status: int | None = None,
    error_message: str | None = None,
    metadata: dict | None = None,
) -> None:
    await pool.execute(
        """
        UPDATE feed_runs
           SET finished_at  = now(),
               status       = $1,
               cursor_after = $2,
               rows_seen    = $3,
               rows_added   = $4,
               rows_updated = $5,
               http_status  = $6,
               error_message = $7,
               metadata     = COALESCE($8, '{}'::jsonb)
         WHERE id = $9
        """,
        status,
        cursor_after,
        rows_seen,
        rows_added,
        rows_updated,
        http_status,
        error_message,
        metadata,
        run_id,
    )


async def latest_cursor(pool: asyncpg.Pool, source: str) -> datetime | None:
    """Return the cursor_after of the last successful run for this source."""
    return await pool.fetchval(
        """
        SELECT cursor_after
          FROM feed_runs
         WHERE source = $1
           AND status = 'success'
           AND cursor_after IS NOT NULL
         ORDER BY started_at DESC
         LIMIT 1
        """,
        source,
    )


def severity_from_score(score: float | None) -> str | None:
    """CVSS v3 score → categorical severity per NVD."""
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
