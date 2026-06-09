"""AAP router — real implementation (P1).

Endpoints:
    POST /api/aap/launch          — launch a job template (mutating)
    GET  /api/aap/jobs/{job_id}   — poll a job's status (read-only)

Replaces the 501 stub from PR #42; the status endpoint lands in
this PR as the "AAP launch v2 — polling" workstream.

Tenant scoping:
    - Launch: `hostname` must be in the caller's allowed_hostnames
      (via tenant_host_mapping). Foreign hostnames return 422.
    - Status: only jobs the caller's tenant launched are visible.
      Ownership is sourced from `system_audit_log` — every launch
      writes a row with (tenant_id, 'aap_job', job_id) so the same
      table that proves "who did what" also enforces "who may see."
      Missing ownership → 404 (no info leak about whether the job
      exists under a different tenant).

MFA: write endpoints require an MFA-verified session (per-route);
read endpoints (status) only require an authenticated session.
Matches the read/write split used in remediation + classification.

Audit: every launch logs (resource='aap_job', id=job_id). Successful
status polls are NOT audited — `AuditMiddleware` only records
mutations and 4xx/5xx responses, so the polling tick doesn't 10x
audit volume. A failed poll (404 from foreign-tenant probe,
502 from AAP outage, etc.) DOES land in `system_audit_log` so the
security signal isn't lost.
"""
from __future__ import annotations

from typing import Annotated, Any

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..core.aap_client import (
    AapError,
    AapNotConfigured,
    get_job,
    launch_job_template,
)
from ..core.portal_db import get_portal_pool
from ..core.rbac import require_role
from ..core.sessions import require_tenant_user, require_tenant_user_mfa
from ..core.tenant_scope import allowed_hostnames


# Router-level dep: any authenticated session. Mutating endpoints
# (POST /launch) add MFA on top. Matches the remediation/
# classification pattern.
router = APIRouter(
    prefix="/aap",
    tags=["aap"],
    dependencies=[Depends(require_tenant_user)],
)


class LaunchRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    framework: str = Field(min_length=1, max_length=100)
    template_id: int = Field(gt=0)


class LaunchResponse(BaseModel):
    job_id: int
    status: str
    url: str | None = None
    started_at: str | None = None


class JobStatusResponse(BaseModel):
    """Curated subset of AAP's job record.

    Intentionally narrow — proxying every AAP field would couple the
    portal contract to AAP's schema. Add fields here when the
    frontend grows a need for them.

    `terminal` is a portal convenience: the frontend can stop polling
    when terminal=true without having to know AAP's state vocabulary.
    """
    job_id: int
    status: str             # pending | waiting | running | successful | failed | error | canceled
    terminal: bool          # caller-facing "stop polling" flag
    failed: bool            # AAP sets this even before status moves out of "running" sometimes
    started: str | None = None
    finished: str | None = None
    elapsed: float | None = None
    url: str | None = None


# Terminal states — frontend can stop polling once a job reaches one
# of these. Kept here (not in aap_client) because it's a portal
# concern, not an AAP fact.
_TERMINAL_STATES = frozenset({"successful", "failed", "error", "canceled"})


@router.post(
    "/launch",
    response_model=LaunchResponse,
    dependencies=[Depends(require_tenant_user_mfa), Depends(require_role("editor"))],
)
async def launch(
    body: LaunchRequest,
    request: Request,
    user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    portal_pool: asyncpg.Pool = Depends(get_portal_pool),
):
    """Launch the named AAP job template against the named host,
    passing the compliance framework through as an extra_var so the
    playbook routes to the right OPA bucket.
    """
    # 1. Tenant scope check — hostname must belong to this tenant.
    allowed = await allowed_hostnames(portal_pool, user["tenant_id"])
    if body.hostname not in allowed:
        # 422 — same shape as a malformed body — keeps the error
        # surface uniform and doesn't leak whether the host exists
        # under a different tenant.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"hostname '{body.hostname}' is not mapped to your tenant. "
                f"Map it under Portal → Host Mappings first."
            ),
        )

    # 2. Hand off to the AAP client. Pass hostname + framework via
    #    extra_vars so the playbook can pick the right OPA endpoint
    #    (security/compliance/ot) and target host.
    extra_vars = {
        "target_host": body.hostname,
        "framework": body.framework,
        # Caller fingerprint — playbooks can echo these back so
        # post-mortem links AAP run → portal user.
        "aac_portal_user_id": str(user["tenant_user_id"]),
        "aac_portal_tenant_id": str(user["tenant_id"]),
    }

    try:
        aap_resp = await launch_job_template(body.template_id, extra_vars)
    except AapNotConfigured as e:
        # 503 — operator hasn't wired AAP_URL/AAP_TOKEN yet.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )
    except AapError as e:
        # The client raises plain AapError with "not found" in the
        # message for AAP's own 404 — surface that as 404 so the
        # frontend can show a useful error; everything else is 502.
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(e),
            )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"AAP launch failed: {e}",
        )

    job_id = int(aap_resp["job"])

    # 3. Audit hook — middleware reads these off request.state.
    request.state.audit_resource = ("aap_job", str(job_id))
    request.state.audit_extra = {
        "template_id": body.template_id,
        "hostname": body.hostname,
        "framework": body.framework,
        "aap_status": aap_resp.get("status"),
    }

    return LaunchResponse(
        job_id=job_id,
        status=aap_resp.get("status", "pending"),
        url=aap_resp.get("url"),
        started_at=aap_resp.get("created"),
    )


async def _tenant_owns_job(
    portal_pool: asyncpg.Pool,
    tenant_id: str,
    job_id: int,
) -> bool:
    """Did this tenant launch this AAP job?

    Sourced from `system_audit_log` — the launch endpoint records
    (resource_type='aap_job', resource_id=str(job_id)) for the
    launching tenant. The audit log is append-only, so this is the
    authoritative ownership record. Returns False if there's no
    audit row, which the caller turns into a 404 (same shape as a
    truly-missing job; no info leak)."""
    found = await portal_pool.fetchval(
        """
        SELECT 1
          FROM system_audit_log
         WHERE tenant_id = $1::uuid
           AND resource_type = 'aap_job'
           AND resource_id = $2
         LIMIT 1
        """,
        str(tenant_id),
        str(job_id),
    )
    return found is not None


@router.get("/jobs/{job_id}", response_model=JobStatusResponse)
async def job_status(
    job_id: int,
    user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    portal_pool: asyncpg.Pool = Depends(get_portal_pool),
):
    """Return the AAP-side status of a job this tenant launched.

    Polling pattern — the frontend hits this on an interval (e.g.
    every 3s) until `status` is in {successful, failed, error,
    canceled}. The response includes a `url` linking to AAP's own
    UI for stdout / artifacts (stream-from-portal is v3).
    """
    # FastAPI's path parser accepts any int (including negative); the
    # positivity guarantee comes from this explicit guard. AAP job IDs
    # are bigserial-allocated and always positive, so 0 / negative is
    # by definition a job that can't exist — surface as 404 without
    # querying AAP or the audit log.
    if job_id <= 0:
        raise HTTPException(status_code=404, detail="job not found")

    if not await _tenant_owns_job(portal_pool, user["tenant_id"], job_id):
        # 404 not 403 — caller shouldn't be able to probe whether
        # job_id exists under another tenant.
        raise HTTPException(status_code=404, detail="job not found")

    try:
        aap_resp = await get_job(job_id)
    except AapNotConfigured as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )
    except AapError as e:
        # AAP-side 404 is possible: the audit log says we launched
        # it, but AAP has pruned the row (long-running portal,
        # AAP-side retention). Surface as 404 so the frontend can
        # show "job no longer in AAP" cleanly.
        if "not found" in str(e).lower():
            raise HTTPException(
                status_code=404,
                detail="job no longer available in AAP (likely pruned by retention)",
            )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"AAP status fetch failed: {e}",
        )

    aap_status = str(aap_resp.get("status", ""))
    return JobStatusResponse(
        job_id=job_id,
        status=aap_status,
        terminal=aap_status in _TERMINAL_STATES,
        failed=bool(aap_resp.get("failed", False)),
        started=aap_resp.get("started"),
        finished=aap_resp.get("finished"),
        elapsed=aap_resp.get("elapsed"),
        url=aap_resp.get("url"),
    )
