"""AAP launch router — stub.

Frontend (frontend/src/lib/api.ts:launchAssessment) calls:
    POST /api/aap/launch
    body: { hostname, framework, template_id }

Returns 501 until the AAP controller integration lands.

Implementation plan:
    - Use `core.config.aap_controller_url` + `aap_verify_ssl`.
    - Auth via AAP_TOKEN (already in env contract).
    - POST to /api/v2/job_templates/{template_id}/launch/ with the
      hostname + framework as extra_vars.
    - Return { job_id } so the frontend can poll status.
    - Audit the launch (actor, template, target host) — required
      for the four-eyes governance pattern.
"""
from fastapi import APIRouter, Depends, HTTPException, status

from ..core.sessions import require_tenant_user_mfa

# Launching an AAP job is an infrastructure-mutation action — requires
# an MFA-verified session, same bar as remediation writes and policy
# publishing.
router = APIRouter(
    prefix="/aap",
    tags=["aap"],
    dependencies=[Depends(require_tenant_user_mfa)],
)


@router.post("/launch")
async def launch():
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "aap/launch is not implemented yet — needs the AAP "
            "Controller integration described in docs/architecture.md"
        ),
    )
