"""
NVD 2.0 feed adapter.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
Incremental: lastModStartDate + lastModEndDate (max 120 days apart).
Pagination: startIndex + resultsPerPage (max 2000).
Rate limit: 5 req / 30s anonymous, 50 req / 30s with NVD_API_KEY.

Usage:
    from src.core.portal_db import get_portal_pool
    from src.feeds.nvd import ingest
    pool = await get_portal_pool()
    summary = await ingest(pool, lookback_days=2)
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg
import httpx

from .common import (
    close_run,
    latest_cursor,
    open_run,
    severity_from_score,
    utcnow,
)

SOURCE = "nvd"
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # NVD max
# Throttle: anonymous 5 req / 30 s = one every 6 s. With key: every 0.6 s.
ANON_INTERVAL_S = 6.5
KEY_INTERVAL_S = 0.7
# NVD requires lastModStartDate / lastModEndDate to be ≤ 120 days apart;
# we slice the lookback into windows when first-run / large lookback.
MAX_WINDOW_DAYS = 119


def _request_headers() -> dict[str, str]:
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _interval() -> float:
    return KEY_INTERVAL_S if os.environ.get("NVD_API_KEY") else ANON_INTERVAL_S


def _iso_nvd(ts: datetime) -> str:
    """NVD wants ISO8601 with milliseconds and no offset suffix."""
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None, float | None]:
    """Return (cvss_v3, severity, cvss_v2)."""
    v3_score: float | None = None
    v3_sev: str | None = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        items = metrics.get(key) or []
        if not items:
            continue
        primary = next((x for x in items if x.get("type") == "Primary"), items[0])
        data = primary.get("cvssData") or {}
        v3_score = data.get("baseScore")
        v3_sev = (data.get("baseSeverity") or "").upper() or severity_from_score(v3_score)
        break

    v2_score: float | None = None
    v2_items = metrics.get("cvssMetricV2") or []
    if v2_items:
        v2_score = (v2_items[0].get("cvssData") or {}).get("baseScore")

    return v3_score, v3_sev, v2_score


def _extract_cpes(configurations: list) -> list[str]:
    out: list[str] = []
    for cfg in configurations or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                cpe = match.get("criteria")
                if cpe and match.get("vulnerable") is True:
                    out.append(cpe)
    return list(dict.fromkeys(out))  # dedupe, preserve order


def _extract_description(descriptions: list) -> str | None:
    for d in descriptions or []:
        if d.get("lang") == "en":
            return d.get("value")
    return None


def _vendor_product_from_cpes(cpes: list[str]) -> tuple[str | None, str | None]:
    """Best-effort vendor/product from the first CPE 2.3 string."""
    for cpe in cpes:
        # cpe:2.3:a:vendor:product:version:...
        parts = cpe.split(":")
        if len(parts) >= 5 and parts[0] == "cpe":
            vendor = parts[3] if parts[3] != "*" else None
            product = parts[4] if parts[4] != "*" else None
            if vendor or product:
                return vendor, product
    return None, None


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    # NVD format: 2024-08-22T13:15:24.487
    try:
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


async def _fetch_window(
    client: httpx.AsyncClient,
    window_start: datetime,
    window_end: datetime,
) -> list[dict]:
    """Pull all vulnerabilities modified in [window_start, window_end)."""
    vulns: list[dict] = []
    start_index = 0
    while True:
        params = {
            "lastModStartDate": _iso_nvd(window_start),
            "lastModEndDate": _iso_nvd(window_end),
            "startIndex": start_index,
            "resultsPerPage": PAGE_SIZE,
        }
        resp = await client.get(NVD_BASE_URL, params=params)
        resp.raise_for_status()
        data = resp.json()
        page = data.get("vulnerabilities") or []
        vulns.extend(page)

        total = int(data.get("totalResults") or 0)
        start_index += len(page)
        if start_index >= total or not page:
            return vulns
        # Be polite — NVD rate limit
        await asyncio.sleep(_interval())


async def _upsert_cve(conn: asyncpg.Connection, vuln: dict) -> tuple[bool, bool]:
    """UPSERT one NVD vulnerability. Returns (added, updated)."""
    cve = vuln.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return False, False

    published = _parse_ts(cve.get("published"))
    last_mod = _parse_ts(cve.get("lastModified"))
    metrics = cve.get("metrics") or {}
    v3_score, v3_sev, v2_score = _extract_cvss(metrics)
    cpes = _extract_cpes(cve.get("configurations") or [])
    description = _extract_description(cve.get("descriptions") or [])
    vendor, product = _vendor_product_from_cpes(cpes)

    row = await conn.fetchrow(
        """
        INSERT INTO cve_events (
            cve_id, cvss_v3, cvss_v3_severity, cvss_v2,
            published_at, last_modified_at,
            vendor, product, affected_cpes, description,
            sources, raw_nvd
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, ARRAY['nvd']::text[], $11::jsonb)
        ON CONFLICT (cve_id) DO UPDATE
          SET cvss_v3          = COALESCE(EXCLUDED.cvss_v3,          cve_events.cvss_v3),
              cvss_v3_severity = COALESCE(EXCLUDED.cvss_v3_severity, cve_events.cvss_v3_severity),
              cvss_v2          = COALESCE(EXCLUDED.cvss_v2,          cve_events.cvss_v2),
              published_at     = COALESCE(EXCLUDED.published_at,     cve_events.published_at),
              last_modified_at = COALESCE(EXCLUDED.last_modified_at, cve_events.last_modified_at),
              vendor           = COALESCE(EXCLUDED.vendor,           cve_events.vendor),
              product          = COALESCE(EXCLUDED.product,          cve_events.product),
              affected_cpes    = CASE
                                   WHEN array_length(EXCLUDED.affected_cpes, 1) > 0
                                   THEN EXCLUDED.affected_cpes
                                   ELSE cve_events.affected_cpes
                                 END,
              description      = COALESCE(EXCLUDED.description, cve_events.description),
              sources          = (
                                   SELECT array_agg(DISTINCT s)
                                     FROM unnest(cve_events.sources || ARRAY['nvd']::text[]) s
                                 ),
              raw_nvd          = EXCLUDED.raw_nvd
        RETURNING (xmax = 0) AS inserted
        """,
        cve_id, v3_score, v3_sev, v2_score,
        published, last_mod,
        vendor, product, cpes, description,
        json.dumps(vuln),
    )

    # References
    for ref in cve.get("references") or []:
        url = ref.get("url")
        if not url:
            continue
        await conn.execute(
            """
            INSERT INTO cve_references (cve_id, url, source, tags)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (cve_id, url) DO NOTHING
            """,
            cve_id,
            url,
            ref.get("source"),
            ref.get("tags") or [],
        )

    inserted = bool(row["inserted"]) if row else False
    return inserted, (not inserted)


async def ingest(
    pool: asyncpg.Pool,
    *,
    lookback_days: int = 2,
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    """Pull NVD updates incrementally and upsert into cve_events.

    Watermark resumption: starts from the cursor_after of the last
    successful run, or now() - lookback_days if no prior run.
    Slices long windows into ≤119-day chunks per NVD constraints.
    """
    now = utcnow()
    cursor_before = await latest_cursor(pool, SOURCE)
    window_start = cursor_before or (now - timedelta(days=lookback_days))

    run_id = await open_run(pool, SOURCE, cursor_before)
    rows_seen = rows_added = rows_updated = 0
    last_http: int | None = None

    try:
        async with httpx.AsyncClient(
            timeout=timeout_s,
            headers=_request_headers(),
        ) as client:
            slice_start = window_start
            while slice_start < now:
                slice_end = min(slice_start + timedelta(days=MAX_WINDOW_DAYS), now)
                page = await _fetch_window(client, slice_start, slice_end)
                last_http = 200
                rows_seen += len(page)

                async with pool.acquire() as conn:
                    async with conn.transaction():
                        for vuln in page:
                            added, updated = await _upsert_cve(conn, vuln)
                            rows_added += int(added)
                            rows_updated += int(updated)

                slice_start = slice_end
                if slice_start < now:
                    await asyncio.sleep(_interval())

        await close_run(
            pool,
            run_id,
            status="success",
            cursor_after=now,
            rows_seen=rows_seen,
            rows_added=rows_added,
            rows_updated=rows_updated,
            http_status=last_http,
        )
        return {
            "status": "success",
            "cursor_before": cursor_before.isoformat() if cursor_before else None,
            "cursor_after": now.isoformat(),
            "rows_seen": rows_seen,
            "rows_added": rows_added,
            "rows_updated": rows_updated,
        }
    except httpx.HTTPStatusError as e:
        await close_run(
            pool, run_id, status="failed",
            rows_seen=rows_seen, rows_added=rows_added, rows_updated=rows_updated,
            http_status=e.response.status_code,
            error_message=f"HTTP {e.response.status_code}: {e.response.text[:500]}",
        )
        return {"status": "failed", "error": str(e)}
    except Exception as e:
        await close_run(
            pool, run_id, status="failed",
            rows_seen=rows_seen, rows_added=rows_added, rows_updated=rows_updated,
            error_message=f"{type(e).__name__}: {e}",
        )
        return {"status": "failed", "error": str(e)}
