"""AAP launch router — real implementation (P1).

Replaces the 501 stub from PR #42.

Endpoint: POST /api/aap/launch
Body:    { hostname, framework, template_id }
Returns: { job_id, status, started_at, url }

Tenant scoping: `hostname` must be in the caller's allowed_hostnames
(via tenant_host_mapping). Foreign hostnames return 422 — same shape
the frontend's hostname picker uses, so the user sees a clear "not
your host" message rather than an opaque AAP error.

MFA gate: launching an AAP job mutates infrastructure — same bar as
remediation writes and policy publishing. The router-level
`require_tenant_user_mfa` dependency keeps this consistent across
P0-D rollout.

Audit: every launch produces a `system_audit_log` row via the
AuditMiddleware (resource = ("aap_job", str(job_id)); extra =
{template_id, hostname, framework, aap_status}). Required for the
four-eyes governance pattern when AAP-launched playbooks change
production state.

v2 (not in this PR): GET /aap/jobs/{id} for status polling, GET
/aap/jobs/{id}/stdout for logs, POST /aap/jobs/{id}/cancel.
"""
from __future__ import annotations

from typing import Annotated, Any

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..core.aap_client import (
    AapError,
    AapNotConfigured,
    launch_job_template,
)
from ..core.portal_db import get_portal_pool
from ..core.sessions import require_tenant_user_mfa
from ..core.tenant_scope import allowed_hostnames


# Launching an AAP job is an infrastructure-mutation action — requires
# an MFA-verified session, same bar as remediation writes and policy
# publishing.
router = APIRouter(
    prefix="/aap",
    tags=["aap"],
    dependencies=[Depends(require_tenant_user_mfa)],
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


@router.post("/launch", response_model=LaunchResponse)
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
