"""
Per-tenant CVE matcher.

For each active tenant, compute the set of CVEs that:
  1. Belong to a bucket the tenant is enrolled in OR a vendor the tenant
     is allow-subscribed to (and not explicitly opt-out vendor-subscribed).
  2. Pass the tenant's severity / KEV / tag-only filter preferences.
  3. Intersect the tenant's cached inventory (CPE first, then
     vendor+product name fallback).

Insert / update one row per (tenant, cve) in `tenant_cve_matches`.
Idempotent: re-running with the same data yields the same matches with
their `delivered_at` / `acknowledged_at` / `suppressed_at` columns
preserved.

For v1, "tag_only" matches (CVE in the right bucket but no inventory
hit) are only inserted if the tenant opted in via
tenant_filter_preferences.deliver_tag_only.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

import asyncpg

# Severity threshold ranking — matches the CHECK in tenant_filter_preferences.
_SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _passes_severity(severity: str | None, threshold: str) -> bool:
    sev = (severity or "NONE").upper()
    return _SEVERITY_RANK.get(sev, 0) >= _SEVERITY_RANK.get(threshold, 2)


# Single SQL query — runs the whole matcher for one tenant in one round trip.
# The query is split into CTEs for readability:
#   prefs          — pull tenant filter prefs (with defaults if no row)
#   enrolled_b     — bucket ids the tenant is enrolled in
#   allow_v        — vendor ids the tenant is allow-subscribed to (allow=true)
#   deny_v         — vendor ids the tenant is opt-out subscribed to (allow=false)
#   tagged_buckets — CVEs tagged with a bucket the tenant is enrolled in
#   tagged_vendors — CVEs tagged with a vendor the tenant is allow-subscribed to
#   tagged_or      — union of the two, minus the deny list, with the matched tags
#   filtered       — apply severity / KEV filter from prefs
#   inv_hits       — intersect with tenant_inventory_catalog (CPE or vendor+product)
#   final          — emit rows; insert via ON CONFLICT preserving delivered_at etc.
_MATCH_SQL = """
WITH prefs AS (
    SELECT
        COALESCE(p.min_severity, 'MEDIUM')             AS min_severity,
        COALESCE(p.deliver_kev_regardless, true)       AS kev_pass_through,
        COALESCE(p.deliver_tag_only, false)            AS deliver_tag_only
      FROM (SELECT 1) z
      LEFT JOIN tenant_filter_preferences p ON p.tenant_id = $1::uuid
),
enrolled_b AS (
    SELECT bucket_id FROM tenant_enrollments WHERE tenant_id = $1::uuid
),
allow_v AS (
    SELECT vendor_id FROM tenant_vendor_subscriptions
     WHERE tenant_id = $1::uuid AND allow = true
),
deny_v AS (
    SELECT vendor_id FROM tenant_vendor_subscriptions
     WHERE tenant_id = $1::uuid AND allow = false
),
tagged_buckets AS (
    SELECT cbt.cve_id, array_agg(DISTINCT b.key) AS bucket_keys
      FROM cve_bucket_tags cbt
      JOIN buckets b ON b.id = cbt.bucket_id
     WHERE cbt.bucket_id IN (SELECT bucket_id FROM enrolled_b)
     GROUP BY cbt.cve_id
),
tagged_vendors AS (
    SELECT cvt.cve_id, array_agg(DISTINCT v.key) AS vendor_keys
      FROM cve_vendor_tags cvt
      JOIN vendors v ON v.id = cvt.vendor_id
     WHERE cvt.vendor_id IN (SELECT vendor_id FROM allow_v)
        OR (
             EXISTS (SELECT 1 FROM enrolled_b)
             AND cvt.vendor_id NOT IN (SELECT vendor_id FROM deny_v)
             AND cvt.vendor_id IN (
                 SELECT bvl.vendor_id
                   FROM bucket_vendor_links bvl
                  WHERE bvl.bucket_id IN (SELECT bucket_id FROM enrolled_b)
             )
           )
     GROUP BY cvt.cve_id
),
candidate_cves AS (
    SELECT
        COALESCE(tb.cve_id, tv.cve_id) AS cve_id,
        COALESCE(tb.bucket_keys, ARRAY[]::text[]) AS bucket_keys,
        COALESCE(tv.vendor_keys, ARRAY[]::text[]) AS vendor_keys
      FROM tagged_buckets tb
      FULL OUTER JOIN tagged_vendors tv USING (cve_id)
),
filtered AS (
    SELECT cc.cve_id, cc.bucket_keys, cc.vendor_keys,
           ce.cvss_v3_severity AS severity, ce.kev_member
      FROM candidate_cves cc
      JOIN cve_events ce ON ce.cve_id = cc.cve_id
      CROSS JOIN prefs p
     WHERE
        (ce.kev_member AND p.kev_pass_through)
        OR
        (COALESCE(ce.cvss_v3_severity, 'NONE') = ANY (
            CASE p.min_severity
                WHEN 'CRITICAL' THEN ARRAY['CRITICAL']
                WHEN 'HIGH'     THEN ARRAY['CRITICAL','HIGH']
                WHEN 'MEDIUM'   THEN ARRAY['CRITICAL','HIGH','MEDIUM']
                WHEN 'LOW'      THEN ARRAY['CRITICAL','HIGH','MEDIUM','LOW']
                ELSE ARRAY['CRITICAL','HIGH','MEDIUM','LOW','NONE']
            END
        ))
),
inv_hits AS (
    -- CPE-match path
    SELECT
        f.cve_id,
        jsonb_agg(DISTINCT jsonb_build_object(
            'vendor', tic.vendor,
            'product', tic.product,
            'version', tic.version,
            'host_count', tic.host_count
        )) AS affected_products,
        COUNT(DISTINCT tic.id)         AS inventory_hits,
        'cpe'::text                    AS match_method
      FROM filtered f
      JOIN cve_events ce ON ce.cve_id = f.cve_id
      JOIN tenant_inventory_catalog tic ON tic.tenant_id = $1::uuid
       AND tic.cpe IS NOT NULL
       AND tic.cpe = ANY(ce.affected_cpes)
     GROUP BY f.cve_id

    UNION

    -- vendor+product fallback (case-insensitive, exact product name)
    SELECT
        f.cve_id,
        jsonb_agg(DISTINCT jsonb_build_object(
            'vendor', tic.vendor,
            'product', tic.product,
            'version', tic.version,
            'host_count', tic.host_count
        )) AS affected_products,
        COUNT(DISTINCT tic.id)         AS inventory_hits,
        'vendor_product'::text         AS match_method
      FROM filtered f
      JOIN cve_events ce ON ce.cve_id = f.cve_id
      JOIN tenant_inventory_catalog tic ON tic.tenant_id = $1::uuid
       AND ce.product IS NOT NULL
       AND lower(tic.product) = lower(ce.product)
     WHERE NOT EXISTS (
         SELECT 1
           FROM tenant_inventory_catalog tic2
          WHERE tic2.tenant_id = $1::uuid
            AND tic2.cpe IS NOT NULL
            AND tic2.cpe = ANY(ce.affected_cpes)
       )
     GROUP BY f.cve_id
),
tag_only AS (
    SELECT f.cve_id,
           '[]'::jsonb AS affected_products,
           0           AS inventory_hits,
           'tag_only'::text AS match_method
      FROM filtered f
     WHERE (SELECT deliver_tag_only FROM prefs)
       AND NOT EXISTS (SELECT 1 FROM inv_hits ih WHERE ih.cve_id = f.cve_id)
),
all_matches AS (
    SELECT * FROM inv_hits
    UNION ALL
    SELECT * FROM tag_only
),
emit AS (
    INSERT INTO tenant_cve_matches
        (tenant_id, cve_id, severity, kev_member,
         matched_buckets, matched_vendors,
         affected_products, inventory_hits, match_method, matched_at)
    SELECT
        $1::uuid,
        am.cve_id,
        f.severity,
        f.kev_member,
        f.bucket_keys,
        f.vendor_keys,
        am.affected_products,
        am.inventory_hits,
        am.match_method,
        now()
      FROM all_matches am
      JOIN filtered f USING (cve_id)
    ON CONFLICT (tenant_id, cve_id) DO UPDATE
        SET severity          = EXCLUDED.severity,
            kev_member        = EXCLUDED.kev_member,
            matched_buckets   = EXCLUDED.matched_buckets,
            matched_vendors   = EXCLUDED.matched_vendors,
            affected_products = EXCLUDED.affected_products,
            inventory_hits    = EXCLUDED.inventory_hits,
            match_method      = EXCLUDED.match_method,
            matched_at        = now()
    RETURNING (xmax = 0) AS inserted
)
SELECT
    COUNT(*)                              AS candidates_seen,
    COUNT(*) FILTER (WHERE inserted)      AS rows_added,
    COUNT(*) FILTER (WHERE NOT inserted)  AS rows_updated
  FROM emit;
"""


async def match_tenant(pool: asyncpg.Pool, tenant_id: UUID) -> dict[str, Any]:
    run_id = await pool.fetchval(
        """
        INSERT INTO match_runs (tenant_id, status)
        VALUES ($1::uuid, 'running')
        RETURNING id
        """,
        tenant_id,
    )
    try:
        row = await pool.fetchrow(_MATCH_SQL, tenant_id)
        await pool.execute(
            """
            UPDATE match_runs
               SET finished_at = now(),
                   status      = 'success',
                   candidates_seen = $1,
                   rows_added  = $2,
                   rows_updated = $3
             WHERE id = $4
            """,
            int(row["candidates_seen"] or 0),
            int(row["rows_added"] or 0),
            int(row["rows_updated"] or 0),
            run_id,
        )
        return {
            "tenant_id": str(tenant_id),
            "status": "success",
            "candidates_seen": int(row["candidates_seen"] or 0),
            "rows_added": int(row["rows_added"] or 0),
            "rows_updated": int(row["rows_updated"] or 0),
        }
    except Exception as e:
        await pool.execute(
            """
            UPDATE match_runs
               SET finished_at = now(),
                   status      = 'failed',
                   error_message = $1
             WHERE id = $2
            """,
            f"{type(e).__name__}: {e}",
            run_id,
        )
        return {"tenant_id": str(tenant_id), "status": "failed", "error": str(e)}


async def match_all_tenants(pool: asyncpg.Pool) -> dict[str, Any]:
    rows = await pool.fetch(
        "SELECT id FROM tenants WHERE status = 'active' ORDER BY created_at",
    )
    if not rows:
        return {"status": "success", "tenants_matched": 0, "results": []}

    results = []
    for r in rows:
        results.append(await match_tenant(pool, r["id"]))
    successes = sum(1 for r in results if r.get("status") == "success")
    return {
        "status": "success" if successes == len(results) else "partial",
        "tenants_matched": successes,
        "tenants_total":   len(results),
        "results": results,
    }
