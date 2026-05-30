"""
CISA Known Exploited Vulnerabilities (KEV) feed adapter.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Format: single JSON document with a `vulnerabilities` array.
Cadence: CISA updates daily; we pull on demand or once a day.

Behavior:
    - For each KEV item, ensure cve_events has a row (insert a stub if
      we haven't seen the CVE from any other feed yet).
    - Set kev_member = true + kev_date_added / kev_due_date /
      kev_required_action / kev_ransomware_use on every matching row.
    - Append 'cisa_kev' to the sources array.
"""
from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any

import asyncpg
import httpx

from .common import close_run, latest_cursor, open_run, utcnow

SOURCE = "cisa_kev"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def _parse_date(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return date.fromisoformat(s)
    except ValueError:
        return None


async def _upsert_kev_item(conn: asyncpg.Connection, item: dict) -> tuple[bool, bool]:
    cve_id = item.get("cveID")
    if not cve_id:
        return False, False

    row = await conn.fetchrow(
        """
        INSERT INTO cve_events (
            cve_id, vendor, product, description,
            kev_member, kev_date_added, kev_due_date,
            kev_required_action, kev_ransomware_use,
            sources, raw_kev
        )
        VALUES ($1, $2, $3, $4, true, $5, $6, $7, $8, ARRAY['cisa_kev']::text[], $9::jsonb)
        ON CONFLICT (cve_id) DO UPDATE
          SET vendor              = COALESCE(cve_events.vendor,  EXCLUDED.vendor),
              product             = COALESCE(cve_events.product, EXCLUDED.product),
              description         = COALESCE(cve_events.description, EXCLUDED.description),
              kev_member          = true,
              kev_date_added      = EXCLUDED.kev_date_added,
              kev_due_date        = EXCLUDED.kev_due_date,
              kev_required_action = EXCLUDED.kev_required_action,
              kev_ransomware_use  = EXCLUDED.kev_ransomware_use,
              sources             = (
                                      SELECT array_agg(DISTINCT s)
                                        FROM unnest(cve_events.sources || ARRAY['cisa_kev']::text[]) s
                                    ),
              raw_kev             = EXCLUDED.raw_kev
        RETURNING (xmax = 0) AS inserted
        """,
        cve_id,
        item.get("vendorProject"),
        item.get("product"),
        item.get("shortDescription"),
        _parse_date(item.get("dateAdded")),
        _parse_date(item.get("dueDate")),
        item.get("requiredAction"),
        item.get("knownRansomwareCampaignUse"),
        json.dumps(item),
    )

    inserted = bool(row["inserted"]) if row else False
    return inserted, (not inserted)


async def ingest(pool: asyncpg.Pool, *, timeout_s: float = 60.0) -> dict[str, Any]:
    now = utcnow()
    cursor_before = await latest_cursor(pool, SOURCE)
    run_id = await open_run(pool, SOURCE, cursor_before)

    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            doc = resp.json()
    except Exception as e:
        await close_run(
            pool, run_id, status="failed",
            error_message=f"{type(e).__name__}: {e}",
        )
        return {"status": "failed", "error": str(e)}

    vulns = doc.get("vulnerabilities") or []
    catalog_version = doc.get("catalogVersion")
    rows_added = rows_updated = 0

    async with pool.acquire() as conn:
        async with conn.transaction():
            for item in vulns:
                added, updated = await _upsert_kev_item(conn, item)
                rows_added += int(added)
                rows_updated += int(updated)

    await close_run(
        pool,
        run_id,
        status="success",
        cursor_after=now,
        rows_seen=len(vulns),
        rows_added=rows_added,
        rows_updated=rows_updated,
        http_status=resp.status_code,
        metadata={"catalog_version": catalog_version},
    )
    return {
        "status": "success",
        "catalog_version": catalog_version,
        "rows_seen": len(vulns),
        "rows_added": rows_added,
        "rows_updated": rows_updated,
    }
