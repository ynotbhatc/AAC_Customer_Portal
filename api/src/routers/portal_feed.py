"""
Customer-facing CVE feed API.

This is what the AAC's EDA polls. Bearer auth per tenant; one
tenant_id in the URL path so each customer is provably reading only
their own matches.

Endpoints (all under /api/portal/v1/):
    GET  /tenants/{tenant_id}/whoami
    GET  /tenants/{tenant_id}/cves?since=&severity=&kev_only=&cursor=&limit=
    POST /tenants/{tenant_id}/cves/{cve_id}/ack
    POST /tenants/{tenant_id}/cves/{cve_id}/suppress      body: {reason}

The /cves endpoint returns matched CVEs + cve_references + any
cve_vendor_remediations whose vendor the tenant is subscribed to. On
read, undelivered rows are stamped delivered_at so the AAC can use
?since=<last successful pull> for incremental polling.
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

import asyncpg
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

from ..core.portal_db import get_portal_pool
from ..core.tenant_auth import require_tenant

router = APIRouter(prefix="/portal/v1", tags=["portal:cve_feed"])

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL", "NONE"]


class SuppressBody(BaseModel):
    reason: str = Field(default="", max_length=500)


# ── whoami ─────────────────────────────────────────────────────────────
@router.get("/tenants/{tenant_id}/whoami")
async def whoami(
    tenant_id: Annotated[str, Path()],
    tenant: Annotated[dict, Depends(require_tenant)],
) -> dict:
    return {
        "tenant_id": str(tenant["tenant_id"]),
        "tenant_display_name": tenant["tenant_display_name"],
        "token_id": tenant["token_id"],
        "scopes": tenant["scopes"],
    }


# ── CVE feed (the main endpoint) ───────────────────────────────────────
@router.get("/tenants/{tenant_id}/cves")
async def list_cves(
    tenant_id: Annotated[str, Path()],
    tenant: Annotated[dict, Depends(require_tenant)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    since: str | None = Query(default=None, description="ISO8601 — only matches matched/updated since"),
    severity: Severity | None = None,
    kev_only: bool = False,
    cursor: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=2000),
    include_acknowledged: bool = False,
    include_suppressed: bool = False,
) -> dict[str, Any]:
    since_ts: datetime | None = None
    if since:
        try:
            since_ts = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid 'since' — expected ISO8601")

    conditions: list[str] = ["m.tenant_id = $1::uuid"]
    args: list = [tenant_id]
    if since_ts is not None:
        args.append(since_ts)
        conditions.append(f"m.matched_at >= ${len(args)}")
    if severity:
        args.append(severity)
        conditions.append(f"m.severity = ${len(args)}")
    if kev_only:
        conditions.append("m.kev_member = true")
    if not include_acknowledged:
        conditions.append("m.acknowledged_at IS NULL")
    if not include_suppressed:
        conditions.append("m.suppressed_at IS NULL")
    args.append(limit + 1)         # +1 so we can tell if there's a next page
    args.append(cursor)

    rows = await pool.fetch(
        f"""
        SELECT m.cve_id, m.severity, m.kev_member,
               m.matched_buckets, m.matched_vendors,
               m.affected_products, m.inventory_hits, m.match_method,
               m.matched_at, m.delivered_at, m.acknowledged_at, m.suppressed_at,
               ce.cvss_v3, ce.cvss_v3_severity, ce.kev_member AS ce_kev,
               ce.kev_date_added, ce.kev_due_date, ce.kev_required_action,
               ce.kev_ransomware_use, ce.published_at, ce.last_modified_at,
               ce.vendor, ce.product, ce.description, ce.sources,
               COALESCE(
                   (SELECT jsonb_agg(jsonb_build_object(
                              'url', cr.url, 'source', cr.source, 'tags', cr.tags
                          ) ORDER BY cr.added_at)
                      FROM cve_references cr
                     WHERE cr.cve_id = m.cve_id),
                   '[]'::jsonb
               ) AS cve_references,
               COALESCE(
                   (SELECT jsonb_agg(jsonb_build_object(
                              'vendor', v.key,
                              'vendor_display_name', v.display_name,
                              'vendor_advisory_id', vr.vendor_advisory_id,
                              'fix_version', vr.fix_version,
                              'patch_url', vr.patch_url,
                              'patch_description', vr.patch_description,
                              'available_at', vr.available_at
                          ) ORDER BY vr.available_at DESC NULLS LAST)
                      FROM cve_vendor_remediations vr
                      JOIN vendors v ON v.id = vr.vendor_id
                     WHERE vr.cve_id = m.cve_id
                       AND v.id IN (
                           SELECT bvl.vendor_id
                             FROM bucket_vendor_links bvl
                             JOIN tenant_enrollments te ON te.bucket_id = bvl.bucket_id
                            WHERE te.tenant_id = $1::uuid
                           UNION
                           SELECT s.vendor_id
                             FROM tenant_vendor_subscriptions s
                            WHERE s.tenant_id = $1::uuid AND s.allow = true
                       )
                       AND v.id NOT IN (
                           SELECT s.vendor_id
                             FROM tenant_vendor_subscriptions s
                            WHERE s.tenant_id = $1::uuid AND s.allow = false
                       )
                   ),
                   '[]'::jsonb
               ) AS vendor_remediations
          FROM tenant_cve_matches m
          JOIN cve_events ce ON ce.cve_id = m.cve_id
         WHERE {' AND '.join(conditions)}
         ORDER BY m.kev_member DESC, m.matched_at DESC
         OFFSET ${len(args)} LIMIT ${len(args) - 1}
        """,
        *args,
    )

    items = [dict(r) for r in rows[:limit]]
    has_more = len(rows) > limit

    # Stamp delivered_at on previously undelivered rows we're about to ship.
    to_stamp = [r["cve_id"] for r in items if r["delivered_at"] is None]
    if to_stamp:
        await pool.execute(
            """
            UPDATE tenant_cve_matches
               SET delivered_at = now()
             WHERE tenant_id = $1::uuid
               AND cve_id = ANY($2::text[])
               AND delivered_at IS NULL
            """,
            tenant_id, to_stamp,
        )
        # Reflect the stamp in the response so the AAC sees the same
        # delivered_at value the DB now holds.
        now_iso = None
        for item in items:
            if item["delivered_at"] is None and item["cve_id"] in set(to_stamp):
                if now_iso is None:
                    now_iso = (await pool.fetchval("SELECT now()")).isoformat()
                item["delivered_at"] = now_iso

    next_cursor = cursor + limit if has_more else None
    return {
        "tenant_id": str(tenant["tenant_id"]),
        "count": len(items),
        "cursor": cursor,
        "next_cursor": next_cursor,
        "served_at": (await pool.fetchval("SELECT now()")).isoformat(),
        "items": items,
    }


# ── ack / suppress ────────────────────────────────────────────────────
async def _require_match(
    pool: asyncpg.Pool, tenant_id: str, cve_id: str,
) -> None:
    found = await pool.fetchval(
        "SELECT 1 FROM tenant_cve_matches WHERE tenant_id = $1::uuid AND cve_id = $2",
        tenant_id, cve_id,
    )
    if not found:
        raise HTTPException(status_code=404, detail="match not found for this tenant")


@router.post("/tenants/{tenant_id}/cves/{cve_id}/ack", status_code=204)
async def acknowledge_cve(
    tenant_id: Annotated[str, Path()],
    cve_id: Annotated[str, Path()],
    tenant: Annotated[dict, Depends(require_tenant)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> None:
    await _require_match(pool, tenant_id, cve_id)
    await pool.execute(
        """
        UPDATE tenant_cve_matches
           SET acknowledged_at = COALESCE(acknowledged_at, now())
         WHERE tenant_id = $1::uuid AND cve_id = $2
        """,
        tenant_id, cve_id,
    )


@router.post("/tenants/{tenant_id}/cves/{cve_id}/suppress", status_code=204)
async def suppress_cve(
    tenant_id: Annotated[str, Path()],
    cve_id: Annotated[str, Path()],
    tenant: Annotated[dict, Depends(require_tenant)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    body: SuppressBody = Body(default_factory=SuppressBody),
) -> None:
    await _require_match(pool, tenant_id, cve_id)
    await pool.execute(
        """
        UPDATE tenant_cve_matches
           SET suppressed_at     = COALESCE(suppressed_at, now()),
               suppression_reason = COALESCE(NULLIF($3, ''), suppression_reason)
         WHERE tenant_id = $1::uuid AND cve_id = $2
        """,
        tenant_id, cve_id, body.reason,
    )
