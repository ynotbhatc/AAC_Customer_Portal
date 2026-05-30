"""
Operator-admin endpoints for the bucket / vendor taxonomy + per-CVE tags.

GET    /api/admin/v1/buckets
GET    /api/admin/v1/vendors
GET    /api/admin/v1/cves/{cve_id}/tags
POST   /api/admin/v1/cves/{cve_id}/tags/buckets/{bucket_key}    (operator override)
DELETE /api/admin/v1/cves/{cve_id}/tags/buckets/{bucket_key}
POST   /api/admin/v1/cves/{cve_id}/tags/vendors/{vendor_key}    (operator override)
DELETE /api/admin/v1/cves/{cve_id}/tags/vendors/{vendor_key}
POST   /api/admin/v1/classify/run?full=true|false
"""
from __future__ import annotations

from typing import Annotated

import asyncpg
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query

from ..core.auth import require_admin
from ..core.portal_db import get_portal_pool
from ..feeds.classifier import classify_recent

router = APIRouter(
    prefix="/admin/v1",
    tags=["admin:classification"],
    dependencies=[Depends(require_admin)],
)


# ── taxonomy reads ────────────────────────────────────────────────────
@router.get("/buckets")
async def list_buckets(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    include_inactive: bool = False,
) -> list[dict]:
    rows = await pool.fetch(
        """
        SELECT b.id, b.key, b.display_name, b.bucket_type, b.sort_order, b.active,
               b.description,
               (SELECT count(*) FROM cve_bucket_tags t WHERE t.bucket_id = b.id) AS cve_count
          FROM buckets b
         WHERE $1::bool OR b.active
         ORDER BY b.sort_order, b.key
        """,
        include_inactive,
    )
    return [dict(r) for r in rows]


@router.get("/vendors")
async def list_vendors(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    include_inactive: bool = False,
) -> list[dict]:
    rows = await pool.fetch(
        """
        SELECT v.id, v.key, v.display_name, v.aliases, v.cpe_vendor_keys,
               v.advisory_id_pattern, v.psirt_url, v.active,
               (SELECT count(*) FROM cve_vendor_tags t WHERE t.vendor_id = v.id) AS cve_count,
               (SELECT array_agg(b.key ORDER BY b.sort_order)
                  FROM bucket_vendor_links bvl
                  JOIN buckets b ON b.id = bvl.bucket_id
                 WHERE bvl.vendor_id = v.id) AS bucket_keys
          FROM vendors v
         WHERE $1::bool OR v.active
         ORDER BY v.display_name
        """,
        include_inactive,
    )
    return [dict(r) for r in rows]


@router.get("/cves/{cve_id}/tags")
async def get_cve_tags(
    cve_id: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    cve = await pool.fetchrow("SELECT cve_id FROM cve_events WHERE cve_id = $1", cve_id)
    if cve is None:
        raise HTTPException(status_code=404, detail="cve not found")

    buckets = await pool.fetch(
        """
        SELECT b.key, b.display_name, b.bucket_type,
               t.confidence, t.method, t.tagged_at
          FROM cve_bucket_tags t
          JOIN buckets b ON b.id = t.bucket_id
         WHERE t.cve_id = $1
         ORDER BY b.sort_order
        """,
        cve_id,
    )
    vendors = await pool.fetch(
        """
        SELECT v.key, v.display_name,
               t.confidence, t.method, t.tagged_at
          FROM cve_vendor_tags t
          JOIN vendors v ON v.id = t.vendor_id
         WHERE t.cve_id = $1
         ORDER BY v.display_name
        """,
        cve_id,
    )
    return {
        "cve_id": cve_id,
        "buckets": [dict(r) for r in buckets],
        "vendors": [dict(r) for r in vendors],
    }


# ── operator overrides ────────────────────────────────────────────────
async def _bucket_id(pool: asyncpg.Pool, bucket_key: str) -> int:
    bid = await pool.fetchval("SELECT id FROM buckets WHERE key = $1", bucket_key)
    if bid is None:
        raise HTTPException(status_code=404, detail=f"bucket '{bucket_key}' not found")
    return bid


async def _vendor_id(pool: asyncpg.Pool, vendor_key: str) -> int:
    vid = await pool.fetchval("SELECT id FROM vendors WHERE key = $1", vendor_key)
    if vid is None:
        raise HTTPException(status_code=404, detail=f"vendor '{vendor_key}' not found")
    return vid


@router.post("/cves/{cve_id}/tags/buckets/{bucket_key}", status_code=201)
async def tag_bucket(
    cve_id: Annotated[str, Path()],
    bucket_key: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    bucket_id = await _bucket_id(pool, bucket_key)
    await pool.execute(
        """
        INSERT INTO cve_bucket_tags (cve_id, bucket_id, confidence, method)
        VALUES ($1, $2, 100, 'operator')
        ON CONFLICT (cve_id, bucket_id) DO UPDATE
          SET confidence = 100,
              method     = 'operator',
              tagged_at  = now()
        """,
        cve_id, bucket_id,
    )
    return {"cve_id": cve_id, "bucket": bucket_key, "method": "operator"}


@router.delete("/cves/{cve_id}/tags/buckets/{bucket_key}", status_code=204)
async def untag_bucket(
    cve_id: Annotated[str, Path()],
    bucket_key: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> None:
    bucket_id = await _bucket_id(pool, bucket_key)
    await pool.execute(
        "DELETE FROM cve_bucket_tags WHERE cve_id = $1 AND bucket_id = $2",
        cve_id, bucket_id,
    )


@router.post("/cves/{cve_id}/tags/vendors/{vendor_key}", status_code=201)
async def tag_vendor(
    cve_id: Annotated[str, Path()],
    vendor_key: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    vendor_id = await _vendor_id(pool, vendor_key)
    await pool.execute(
        """
        INSERT INTO cve_vendor_tags (cve_id, vendor_id, confidence, method)
        VALUES ($1, $2, 100, 'operator')
        ON CONFLICT (cve_id, vendor_id) DO UPDATE
          SET confidence = 100,
              method     = 'operator',
              tagged_at  = now()
        """,
        cve_id, vendor_id,
    )
    return {"cve_id": cve_id, "vendor": vendor_key, "method": "operator"}


@router.delete("/cves/{cve_id}/tags/vendors/{vendor_key}", status_code=204)
async def untag_vendor(
    cve_id: Annotated[str, Path()],
    vendor_key: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> None:
    vendor_id = await _vendor_id(pool, vendor_key)
    await pool.execute(
        "DELETE FROM cve_vendor_tags WHERE cve_id = $1 AND vendor_id = $2",
        cve_id, vendor_id,
    )


# ── classifier control ────────────────────────────────────────────────
@router.post("/classify/run", status_code=202)
async def trigger_classify(
    background: BackgroundTasks,
    full: bool = Query(default=False, description="re-tag the entire catalog"),
) -> dict:
    async def _go() -> None:
        from ..core.portal_db import get_portal_pool as _pool  # avoid circular at import time
        pool = await _pool()
        await classify_recent(pool, full_rebuild=full)

    background.add_task(_go)
    return {"status": "accepted", "full_rebuild": full}
