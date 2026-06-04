"""
Operator-admin endpoints for per-tenant enrollment + matcher controls.

Bucket enrollment   — coarse opt-in to a category (rhel, ot_scada, ...)
Vendor subscription — finer-grained opt-in / opt-out per vendor
Filter preferences  — severity threshold, KEV pass-through, tag-only
                      delivery, auto-apply-KEV
Inventory + match   — trigger background pulls / matcher runs
Match inspection    — list a tenant's matches with filtering
"""
from __future__ import annotations

from typing import Annotated, Literal

import asyncpg
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query, Response
from pydantic import BaseModel, Field

from ..core.auth import require_admin
from ..core.portal_db import get_portal_pool
from ..feeds.inventory_puller import pull_all_tenants
from ..feeds.matcher import match_all_tenants, match_tenant

router = APIRouter(
    prefix="/admin/v1/tenants/{tenant_id}",
    tags=["admin:enrollments"],
    dependencies=[Depends(require_admin)],
)

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"]


class PreferencesBody(BaseModel):
    min_severity: Severity | None = None
    deliver_kev_regardless: bool | None = None
    deliver_tag_only: bool | None = None
    auto_apply_kev: bool | None = None


class VendorSubBody(BaseModel):
    allow: bool = Field(default=True)


async def _require_tenant(pool: asyncpg.Pool, tenant_id: str) -> None:
    found = await pool.fetchval("SELECT 1 FROM tenants WHERE id = $1::uuid", tenant_id)
    if not found:
        raise HTTPException(status_code=404, detail="tenant not found")


# ── enrollments (buckets) ─────────────────────────────────────────────
@router.get("/enrollments")
async def list_enrollments(
    tenant_id: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> list[dict]:
    await _require_tenant(pool, tenant_id)
    rows = await pool.fetch(
        """
        SELECT b.key, b.display_name, b.bucket_type, e.enrolled_at
          FROM tenant_enrollments e
          JOIN buckets b ON b.id = e.bucket_id
         WHERE e.tenant_id = $1::uuid
         ORDER BY b.sort_order
        """,
        tenant_id,
    )
    return [dict(r) for r in rows]


@router.post("/enrollments/{bucket_key}", status_code=201)
async def enroll_bucket(
    tenant_id: Annotated[str, Path()],
    bucket_key: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    await _require_tenant(pool, tenant_id)
    bucket_id = await pool.fetchval(
        "SELECT id FROM buckets WHERE key = $1 AND active",
        bucket_key,
    )
    if bucket_id is None:
        raise HTTPException(status_code=404, detail=f"bucket '{bucket_key}' not found or inactive")
    await pool.execute(
        """
        INSERT INTO tenant_enrollments (tenant_id, bucket_id)
        VALUES ($1::uuid, $2)
        ON CONFLICT DO NOTHING
        """,
        tenant_id, bucket_id,
    )
    return {"tenant_id": tenant_id, "bucket": bucket_key}


@router.delete("/enrollments/{bucket_key}", status_code=204, response_class=Response, response_model=None)
async def unenroll_bucket(
    tenant_id: Annotated[str, Path()],
    bucket_key: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> None:
    await _require_tenant(pool, tenant_id)
    bucket_id = await pool.fetchval("SELECT id FROM buckets WHERE key = $1", bucket_key)
    if bucket_id is None:
        raise HTTPException(status_code=404, detail=f"bucket '{bucket_key}' not found")
    await pool.execute(
        "DELETE FROM tenant_enrollments WHERE tenant_id = $1::uuid AND bucket_id = $2",
        tenant_id, bucket_id,
    )


# ── vendor subscriptions ──────────────────────────────────────────────
@router.get("/vendor-subscriptions")
async def list_vendor_subs(
    tenant_id: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> list[dict]:
    await _require_tenant(pool, tenant_id)
    rows = await pool.fetch(
        """
        SELECT v.key, v.display_name, s.allow, s.subscribed_at
          FROM tenant_vendor_subscriptions s
          JOIN vendors v ON v.id = s.vendor_id
         WHERE s.tenant_id = $1::uuid
         ORDER BY v.display_name
        """,
        tenant_id,
    )
    return [dict(r) for r in rows]


@router.put("/vendor-subscriptions/{vendor_key}")
async def set_vendor_sub(
    tenant_id: Annotated[str, Path()],
    vendor_key: Annotated[str, Path()],
    body: VendorSubBody,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    await _require_tenant(pool, tenant_id)
    vendor_id = await pool.fetchval(
        "SELECT id FROM vendors WHERE key = $1 AND active",
        vendor_key,
    )
    if vendor_id is None:
        raise HTTPException(status_code=404, detail=f"vendor '{vendor_key}' not found or inactive")
    await pool.execute(
        """
        INSERT INTO tenant_vendor_subscriptions (tenant_id, vendor_id, allow)
        VALUES ($1::uuid, $2, $3)
        ON CONFLICT (tenant_id, vendor_id) DO UPDATE
          SET allow = EXCLUDED.allow,
              subscribed_at = now()
        """,
        tenant_id, vendor_id, body.allow,
    )
    return {"tenant_id": tenant_id, "vendor": vendor_key, "allow": body.allow}


@router.delete("/vendor-subscriptions/{vendor_key}", status_code=204, response_class=Response, response_model=None)
async def remove_vendor_sub(
    tenant_id: Annotated[str, Path()],
    vendor_key: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> None:
    await _require_tenant(pool, tenant_id)
    vendor_id = await pool.fetchval("SELECT id FROM vendors WHERE key = $1", vendor_key)
    if vendor_id is None:
        raise HTTPException(status_code=404, detail=f"vendor '{vendor_key}' not found")
    await pool.execute(
        "DELETE FROM tenant_vendor_subscriptions WHERE tenant_id = $1::uuid AND vendor_id = $2",
        tenant_id, vendor_id,
    )


# ── filter preferences ────────────────────────────────────────────────
@router.get("/preferences")
async def get_preferences(
    tenant_id: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    await _require_tenant(pool, tenant_id)
    row = await pool.fetchrow(
        "SELECT * FROM tenant_filter_preferences WHERE tenant_id = $1::uuid",
        tenant_id,
    )
    if row is None:
        return {
            "tenant_id": tenant_id,
            "min_severity": "MEDIUM",
            "deliver_kev_regardless": True,
            "deliver_tag_only": False,
            "auto_apply_kev": False,
            "defaults": True,
        }
    return {**dict(row), "defaults": False}


@router.put("/preferences")
async def set_preferences(
    tenant_id: Annotated[str, Path()],
    body: PreferencesBody,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> dict:
    await _require_tenant(pool, tenant_id)
    existing = await pool.fetchrow(
        "SELECT * FROM tenant_filter_preferences WHERE tenant_id = $1::uuid",
        tenant_id,
    )
    base = (
        dict(existing) if existing else
        {
            "min_severity": "MEDIUM",
            "deliver_kev_regardless": True,
            "deliver_tag_only": False,
            "auto_apply_kev": False,
        }
    )
    merged = {**base, **{k: v for k, v in body.model_dump().items() if v is not None}}
    await pool.execute(
        """
        INSERT INTO tenant_filter_preferences
            (tenant_id, min_severity, deliver_kev_regardless,
             deliver_tag_only, auto_apply_kev, updated_at)
        VALUES ($1::uuid, $2, $3, $4, $5, now())
        ON CONFLICT (tenant_id) DO UPDATE
          SET min_severity            = EXCLUDED.min_severity,
              deliver_kev_regardless  = EXCLUDED.deliver_kev_regardless,
              deliver_tag_only        = EXCLUDED.deliver_tag_only,
              auto_apply_kev          = EXCLUDED.auto_apply_kev,
              updated_at              = now()
        """,
        tenant_id,
        merged["min_severity"],
        merged["deliver_kev_regardless"],
        merged["deliver_tag_only"],
        merged["auto_apply_kev"],
    )
    return {"tenant_id": tenant_id, **{k: merged[k] for k in (
        "min_severity", "deliver_kev_regardless",
        "deliver_tag_only", "auto_apply_kev",
    )}}


# ── matches inspection ────────────────────────────────────────────────
@router.get("/matches")
async def list_matches(
    tenant_id: Annotated[str, Path()],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    severity: Severity | None = None,
    kev_only: bool = False,
    undelivered_only: bool = False,
    limit: int = Query(default=100, ge=1, le=2000),
) -> list[dict]:
    await _require_tenant(pool, tenant_id)
    conditions: list[str] = ["m.tenant_id = $1::uuid"]
    args: list = [tenant_id]
    if severity:
        args.append(severity)
        conditions.append(f"m.severity = ${len(args)}")
    if kev_only:
        conditions.append("m.kev_member = true")
    if undelivered_only:
        conditions.append("m.delivered_at IS NULL")
    args.append(limit)
    rows = await pool.fetch(
        f"""
        SELECT m.cve_id, m.severity, m.kev_member,
               m.matched_buckets, m.matched_vendors,
               m.affected_products, m.inventory_hits, m.match_method,
               m.matched_at, m.delivered_at, m.acknowledged_at, m.suppressed_at,
               ce.cvss_v3, ce.published_at, ce.last_modified_at
          FROM tenant_cve_matches m
          JOIN cve_events ce ON ce.cve_id = m.cve_id
         WHERE {' AND '.join(conditions)}
         ORDER BY m.kev_member DESC, m.matched_at DESC
         LIMIT ${len(args)}
        """,
        *args,
    )
    return [dict(r) for r in rows]


# ── trigger inventory pull + matcher ──────────────────────────────────
@router.post("/inventory/pull", status_code=202)
async def trigger_pull_for_tenant(
    tenant_id: Annotated[str, Path()],
    background: BackgroundTasks,
) -> dict:
    async def _go() -> None:
        from ..core.portal_db import get_portal_pool as _pool
        pool = await _pool()
        await pull_all_tenants(pool)   # pulls all; cheap enough at v1 scale
    background.add_task(_go)
    return {"status": "accepted", "tenant_id": tenant_id}


@router.post("/matches/run", status_code=202)
async def trigger_match_for_tenant(
    tenant_id: Annotated[str, Path()],
    background: BackgroundTasks,
) -> dict:
    from uuid import UUID
    try:
        uid = UUID(tenant_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid tenant_id")

    async def _go() -> None:
        from ..core.portal_db import get_portal_pool as _pool
        pool = await _pool()
        await match_tenant(pool, uid)
    background.add_task(_go)
    return {"status": "accepted", "tenant_id": tenant_id}


# ── ops-wide helpers (no tenant_id required) ──────────────────────────
ops_router = APIRouter(
    prefix="/admin/v1/ops",
    tags=["admin:ops"],
    dependencies=[Depends(require_admin)],
)


@ops_router.post("/pull-all-inventories", status_code=202)
async def trigger_pull_all(background: BackgroundTasks) -> dict:
    async def _go() -> None:
        from ..core.portal_db import get_portal_pool as _pool
        pool = await _pool()
        await pull_all_tenants(pool)
    background.add_task(_go)
    return {"status": "accepted"}


@ops_router.post("/match-all-tenants", status_code=202)
async def trigger_match_all(background: BackgroundTasks) -> dict:
    async def _go() -> None:
        from ..core.portal_db import get_portal_pool as _pool
        pool = await _pool()
        await match_all_tenants(pool)
    background.add_task(_go)
    return {"status": "accepted"}
