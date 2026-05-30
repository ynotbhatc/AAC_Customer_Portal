"""
CVE → (vendor, bucket) auto-classifier.

Three-pass heuristic, idempotent. Operator-method tags are preserved —
the auto pass uses ON CONFLICT DO NOTHING so it never overwrites a
manual tag.

Pass 1 — exact vendor match
    cve_events.vendor matched case-insensitively against vendors.aliases.

Pass 2 — CPE vendor match
    Any cve_events.affected_cpes element where cpe parts[3]
    (the vendor field of a CPE 2.3 string) matches a vendors.cpe_vendor_keys
    element.

Pass 3 — bucket derivation
    For every vendor tag set on a CVE, copy the vendor's
    bucket_vendor_links into cve_bucket_tags.

The classifier runs after each successful feed pull; the runner calls
`classify_recent(pool, since)` with the cursor advance window so we don't
re-process the entire catalog every run.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg

from .common import utcnow


async def classify_recent(
    pool: asyncpg.Pool,
    *,
    since: datetime | None = None,
    full_rebuild: bool = False,
) -> dict[str, Any]:
    """Tag CVEs modified at-or-after `since` (default: last 1d).

    full_rebuild=True ignores `since` and tags every cve_events row;
    useful after taxonomy changes.
    """
    if full_rebuild:
        since_clause = ""
        args: list = []
    else:
        if since is None:
            since = utcnow() - timedelta(days=1)
        args = [since]
        since_clause = "WHERE COALESCE(c.updated_at, c.received_at) >= $1"

    async with pool.acquire() as conn:
        async with conn.transaction():
            # ── Pass 1: vendor alias match ──────────────────────────────
            vendor_alias_added = await conn.fetchval(
                f"""
                WITH inserted AS (
                    INSERT INTO cve_vendor_tags (cve_id, vendor_id, confidence, method)
                    SELECT c.cve_id, v.id, 90, 'auto:vendor_alias'
                      FROM cve_events c
                      JOIN vendors v
                        ON c.vendor IS NOT NULL
                       AND lower(c.vendor) = ANY (
                           SELECT lower(unnest(v.aliases))
                       )
                       AND v.active
                      {since_clause}
                    ON CONFLICT (cve_id, vendor_id) DO NOTHING
                    RETURNING 1
                )
                SELECT COUNT(*) FROM inserted
                """,
                *args,
            )

            # ── Pass 2: CPE vendor key match ────────────────────────────
            cpe_vendor_added = await conn.fetchval(
                f"""
                WITH cpe_vendors AS (
                    SELECT c.cve_id, split_part(cpe, ':', 4) AS cpe_vendor
                      FROM cve_events c
                      CROSS JOIN LATERAL unnest(c.affected_cpes) AS cpe
                      {since_clause}
                ),
                inserted AS (
                    INSERT INTO cve_vendor_tags (cve_id, vendor_id, confidence, method)
                    SELECT DISTINCT cv.cve_id, v.id, 80, 'auto:cpe_vendor'
                      FROM cpe_vendors cv
                      JOIN vendors v
                        ON cv.cpe_vendor = ANY (v.cpe_vendor_keys)
                       AND v.active
                     WHERE cv.cpe_vendor != '' AND cv.cpe_vendor != '*'
                    ON CONFLICT (cve_id, vendor_id) DO NOTHING
                    RETURNING 1
                )
                SELECT COUNT(*) FROM inserted
                """,
                *args,
            )

            # ── Pass 3: derive buckets from vendor tags ─────────────────
            bucket_added = await conn.fetchval(
                f"""
                WITH targets AS (
                    SELECT c.cve_id
                      FROM cve_events c
                      {since_clause}
                ),
                inserted AS (
                    INSERT INTO cve_bucket_tags (cve_id, bucket_id, confidence, method)
                    SELECT DISTINCT t.cve_id, bvl.bucket_id, 75, 'auto:via_vendor'
                      FROM targets t
                      JOIN cve_vendor_tags vt ON vt.cve_id = t.cve_id
                      JOIN bucket_vendor_links bvl ON bvl.vendor_id = vt.vendor_id
                      JOIN buckets b ON b.id = bvl.bucket_id AND b.active
                    ON CONFLICT (cve_id, bucket_id) DO NOTHING
                    RETURNING 1
                )
                SELECT COUNT(*) FROM inserted
                """,
                *args,
            )

    return {
        "status": "success",
        "since": since.isoformat() if since else None,
        "full_rebuild": full_rebuild,
        "vendor_alias_added": int(vendor_alias_added or 0),
        "cpe_vendor_added":   int(cpe_vendor_added or 0),
        "bucket_added":       int(bucket_added or 0),
    }
