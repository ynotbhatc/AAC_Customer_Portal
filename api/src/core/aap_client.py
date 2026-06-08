"""AAP Controller client.

Thin async wrapper over the AAP 2.6 Controller REST API. The portal
needs exactly one operation today — launching a job template — but
the client is structured so adding `get_job(id)`, `cancel_job(id)`,
and other read calls in v2 is one method, not a refactor.

Auth: Bearer token (long-lived OAuth2 application token). Issued
manually in AAP UI; rotation is out-of-scope here. The token sits
in env (`AAP_TOKEN`) so secrets-manager migration (P0-D4) only
has to touch `config.py`.

Errors: every failure raises `AapError`. The router translates
into HTTP 502 — AAP is upstream, the portal can't be 5xx for an
AAP outage. The error message is logged in audit_extra so a
post-mortem can correlate.

v1 surface:
    launch_job_template(template_id, extra_vars) -> dict
    get_job(job_id) -> dict

v2 (later):
    cancel_job(id), get_job_stdout(id), list_recent_jobs(template_id)
"""
from __future__ import annotations

from typing import Any

import httpx

from .config import get_settings


class AapError(RuntimeError):
    """Any failure talking to the AAP Controller — network, 4xx, 5xx,
    malformed response. Routers translate to 502."""


class AapNotConfigured(AapError):
    """aap_url or aap_token missing. Translated to 503 by the router
    so operators see a clear "this deployment hasn't wired AAP yet"
    instead of a generic 502."""


# AAP 2.6 endpoints. Keep on /api/v2/ — gateway paths
# (/api/controller/v2/) work too but are an unstable surface during
# 2.5→2.6 migrations; v2 is the long-stable controller route.
_LAUNCH_PATH_TMPL = "/api/v2/job_templates/{template_id}/launch/"
_JOB_PATH_TMPL = "/api/v2/jobs/{job_id}/"


async def launch_job_template(
    template_id: int,
    extra_vars: dict[str, Any],
    *,
    timeout_sec: float = 15.0,
) -> dict[str, Any]:
    """Launch an AAP job template.

    Returns the raw response dict from AAP, which includes:
        job: int        — the new job ID (use this to poll)
        url: str        — controller URL of the job
        status: str     — "pending" immediately after launch

    Raises:
        AapNotConfigured: AAP_URL or AAP_TOKEN missing.
        AapError: HTTP error, timeout, or malformed response.
    """
    settings = get_settings()
    if not settings.aap_url or not settings.aap_token:
        raise AapNotConfigured(
            "AAP integration not configured — set AAP_URL and AAP_TOKEN."
        )

    url = settings.aap_url.rstrip("/") + _LAUNCH_PATH_TMPL.format(
        template_id=template_id
    )
    headers = {
        "Authorization": f"Bearer {settings.aap_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    body = {"extra_vars": extra_vars}

    try:
        async with httpx.AsyncClient(
            verify=settings.aap_verify_ssl,
            timeout=timeout_sec,
        ) as client:
            r = await client.post(url, headers=headers, json=body)
    except httpx.HTTPError as e:
        # Network-level: DNS, connect, read timeout, etc.
        raise AapError(f"AAP request failed: {e}") from e

    if r.status_code == 404:
        # Distinct error so the router can 404 vs 502 — a missing
        # template is a caller-fixable problem.
        raise AapError(f"AAP job template {template_id} not found")
    if r.status_code >= 400:
        # Truncate the body so a stray HTML error page doesn't blow
        # up logs; AAP normally returns JSON.
        snippet = (r.text or "")[:500]
        raise AapError(
            f"AAP returned HTTP {r.status_code}: {snippet}"
        )

    try:
        data = r.json()
    except ValueError as e:
        raise AapError(f"AAP returned non-JSON response: {e}") from e

    # Sanity: the launch response must include a job id we can
    # surface to the frontend.
    if not isinstance(data, dict) or "job" not in data:
        raise AapError(
            f"AAP launch response missing 'job' field: {list(data)[:8]}"
        )

    return data


async def get_job(
    job_id: int,
    *,
    timeout_sec: float = 10.0,
) -> dict[str, Any]:
    """Fetch a job's current state from AAP.

    Returns the raw response dict; the router surfaces a curated
    subset to the frontend (status, started, finished,
    elapsed, failed). AAP's full job record carries many fields
    (extra_vars, stdout truncated, etc.) — we don't proxy all of
    them to keep the contract narrow.

    Raises:
        AapNotConfigured: AAP_URL or AAP_TOKEN missing.
        AapError: HTTP error, timeout, or malformed response.
                  A 404 surfaces with "not found" in the message
                  so the router can translate to 404 (the job was
                  never created OR has been pruned by AAP retention).
    """
    settings = get_settings()
    if not settings.aap_url or not settings.aap_token:
        raise AapNotConfigured(
            "AAP integration not configured — set AAP_URL and AAP_TOKEN."
        )

    url = settings.aap_url.rstrip("/") + _JOB_PATH_TMPL.format(job_id=job_id)
    headers = {
        "Authorization": f"Bearer {settings.aap_token}",
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(
            verify=settings.aap_verify_ssl,
            timeout=timeout_sec,
        ) as client:
            r = await client.get(url, headers=headers)
    except httpx.HTTPError as e:
        raise AapError(f"AAP request failed: {e}") from e

    if r.status_code == 404:
        raise AapError(f"AAP job {job_id} not found")
    if r.status_code >= 400:
        snippet = (r.text or "")[:500]
        raise AapError(f"AAP returned HTTP {r.status_code}: {snippet}")

    try:
        data = r.json()
    except ValueError as e:
        raise AapError(f"AAP returned non-JSON response: {e}") from e

    if not isinstance(data, dict) or "status" not in data:
        raise AapError(
            f"AAP job response missing 'status' field: {list(data)[:8]}"
        )
    return data
