"""
Per-tenant inventory puller.

For every active tenant with `aac_bridge_url` set, call the bridge's
`GET /api/aac/v1/inventory_catalog` with the most recent active token,
paginate through results, and upsert into `tenant_inventory_catalog`.
Open/close a `tenant_pull_runs` row for each attempt.

Designed to run after the upstream feed pulls and before the matcher.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import asyncpg
import httpx

from .common import utcnow


PULL_PATH = "/api/aac/v1/inventory_catalog"
WHOAMI_PATH = "/api/aac/v1/whoami"


async def _tenants_to_pull(pool: asyncpg.Pool) -> list[dict]:
    rows = await pool.fetch(
        """
        SELECT t.id, t.display_name, t.aac_bridge_url, t.aac_bridge_verify_ssl,
               (SELECT token_id          FROM tenant_tokens tt
                 WHERE tt.tenant_id = t.id AND tt.revoked_at IS NULL
                   AND 'inventory_pull' = ANY(tt.scopes)
                 ORDER BY tt.created_at DESC LIMIT 1) AS token_id,
               (SELECT token_secret_plaintext FROM tenant_tokens tt
                 WHERE tt.tenant_id = t.id AND tt.revoked_at IS NULL
                   AND 'inventory_pull' = ANY(tt.scopes)
                 ORDER BY tt.created_at DESC LIMIT 1) AS token_secret
          FROM tenants t
         WHERE t.status = 'active'
           AND t.aac_bridge_url IS NOT NULL
        """
    )
    return [dict(r) for r in rows]


async def _open_pull_run(pool: asyncpg.Pool, tenant_id: UUID) -> int:
    row = await pool.fetchrow(
        """
        INSERT INTO tenant_pull_runs (tenant_id, status)
        VALUES ($1, 'running')
        RETURNING id
        """,
        tenant_id,
    )
    return row["id"]


async def _close_pull_run(
    pool: asyncpg.Pool,
    run_id: int,
    *,
    status: str,
    rows_pulled: int | None = None,
    bridge_version: str | None = None,
    http_status: int | None = None,
    error_message: str | None = None,
) -> None:
    await pool.execute(
        """
        UPDATE tenant_pull_runs
           SET finished_at = now(),
               status      = $1,
               rows_pulled = $2,
               bridge_version = $3,
               http_status = $4,
               error_message = $5
         WHERE id = $6
        """,
        status, rows_pulled, bridge_version, http_status, error_message, run_id,
    )


async def _replace_tenant_catalog(
    pool: asyncpg.Pool,
    tenant_id: UUID,
    rows: list[dict],
) -> int:
    """Idempotent rewrite of one tenant's inventory_catalog cache.

    We DELETE then INSERT inside a single transaction — simpler than
    diff-and-merge for v1, and the catalogs are small (~hundreds of rows
    per tenant). Switch to upsert + tombstone later if pulls get heavy.
    """
    if not rows:
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "DELETE FROM tenant_inventory_catalog WHERE tenant_id = $1",
                    tenant_id,
                )
        return 0

    def _parse_ts(s: str | None) -> datetime | None:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    records = [
        (
            tenant_id,
            r.get("vendor") or "unknown",
            r["product"],
            r["version"],
            r.get("cpe"),
            r.get("host_count"),
            r.get("source") or "auto",
            _parse_ts(r.get("first_seen_at")),
            _parse_ts(r.get("last_seen_at")),
        )
        for r in rows
        if r.get("product") and r.get("version")
    ]

    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "DELETE FROM tenant_inventory_catalog WHERE tenant_id = $1",
                tenant_id,
            )
            await conn.executemany(
                """
                INSERT INTO tenant_inventory_catalog
                    (tenant_id, vendor, product, version, cpe,
                     host_count, source, aac_first_seen_at, aac_last_seen_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (tenant_id, vendor, product, version, source) DO UPDATE
                  SET cpe                 = EXCLUDED.cpe,
                      host_count          = EXCLUDED.host_count,
                      aac_first_seen_at   = EXCLUDED.aac_first_seen_at,
                      aac_last_seen_at    = EXCLUDED.aac_last_seen_at,
                      pulled_at           = now()
                """,
                records,
            )
    return len(records)


async def _pull_one_tenant(
    pool: asyncpg.Pool,
    tenant: dict,
    *,
    timeout_s: float,
    page_limit: int,
) -> dict[str, Any]:
    tenant_id: UUID = tenant["id"]
    bridge_url: str = tenant["aac_bridge_url"].rstrip("/")
    verify_ssl: bool = tenant["aac_bridge_verify_ssl"]
    token_id = tenant["token_id"]
    token_secret = tenant["token_secret"]

    run_id = await _open_pull_run(pool, tenant_id)

    if not token_secret:
        await _close_pull_run(
            pool, run_id, status="failed",
            error_message="no active inventory_pull token (token_secret_plaintext is null)",
        )
        return {"tenant_id": str(tenant_id), "status": "failed",
                "error": "no active token"}

    headers = {
        "Authorization": f"Bearer {token_secret}",
        "X-Token-Id": token_id,
        "Accept": "application/json",
    }
    bridge_version: str | None = None
    last_http: int | None = None
    all_rows: list[dict] = []

    try:
        async with httpx.AsyncClient(
            timeout=timeout_s, verify=verify_ssl, headers=headers,
        ) as client:
            cursor = 0
            while True:
                resp = await client.get(
                    f"{bridge_url}{PULL_PATH}",
                    params={"cursor": cursor, "limit": page_limit},
                )
                last_http = resp.status_code
                resp.raise_for_status()
                payload = resp.json()
                page = payload.get("catalog") or []
                all_rows.extend(page)
                next_cursor = payload.get("next_cursor")
                if next_cursor is None or not page:
                    break
                cursor = int(next_cursor)
                # tiny safety: don't loop forever on a broken bridge
                if len(all_rows) > 250_000:
                    break

            # Capture bridge version from healthz (best-effort, non-fatal)
            try:
                hz = await client.get(f"{bridge_url}/api/aac/v1/healthz")
                if hz.status_code == 200:
                    bridge_version = hz.json().get("version")
            except Exception:
                pass

        rows_written = await _replace_tenant_catalog(pool, tenant_id, all_rows)
        await _close_pull_run(
            pool, run_id, status="success",
            rows_pulled=rows_written, bridge_version=bridge_version,
            http_status=last_http,
        )
        return {
            "tenant_id": str(tenant_id),
            "status": "success",
            "rows_pulled": rows_written,
            "bridge_version": bridge_version,
        }
    except httpx.HTTPStatusError as e:
        await _close_pull_run(
            pool, run_id, status="failed",
            http_status=e.response.status_code,
            error_message=f"HTTP {e.response.status_code}: {e.response.text[:500]}",
        )
        return {"tenant_id": str(tenant_id), "status": "failed", "http_status": e.response.status_code}
    except Exception as e:
        await _close_pull_run(
            pool, run_id, status="failed",
            error_message=f"{type(e).__name__}: {e}",
        )
        return {"tenant_id": str(tenant_id), "status": "failed", "error": str(e)}


async def pull_all_tenants(
    pool: asyncpg.Pool,
    *,
    timeout_s: float = 30.0,
    page_limit: int = 10000,
    concurrency: int = 5,
) -> dict[str, Any]:
    tenants = await _tenants_to_pull(pool)
    if not tenants:
        return {"status": "success", "tenants_pulled": 0, "results": []}

    sem = asyncio.Semaphore(concurrency)

    async def _gated(t: dict) -> dict:
        async with sem:
            return await _pull_one_tenant(
                pool, t, timeout_s=timeout_s, page_limit=page_limit,
            )

    results = await asyncio.gather(*(_gated(t) for t in tenants))
    successes = sum(1 for r in results if r.get("status") == "success")
    return {
        "status": "success" if successes == len(results) else "partial",
        "tenants_pulled": successes,
        "tenants_total":  len(results),
        "results": results,
    }
