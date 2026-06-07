"""Remediation router — stub.

Frontend (frontend/src/lib/api.ts) calls:
    GET    /api/remediation              — list items
    PATCH  /api/remediation/{id}         — update status

These endpoints aren't implemented yet. Returning 501 here so the
frontend gets a structured "not implemented" error rather than a 404
(which previously made the page look broken instead of intentionally
gated).

Implementation plan when ready:
    - Add `remediation_items` table (id, hostname, framework,
      control_id, description, severity, status, assigned_to,
      created_at, updated_at).
    - On every assessment write, derive open items from failed
      controls and upsert. Resolve when the next assessment has the
      same control passing.
    - Add the approval/four-eyes step the reviewer agent called out:
      `pending_approval` status between `in_progress` and `resolved`,
      with `approved_by` recorded in the audit log.
    - Gate PATCH behind the auth dependency once auth is in place.
"""
from fastapi import APIRouter, Depends, HTTPException, status

from ..core.sessions import require_tenant_user, require_tenant_user_mfa

# Read = logged-in user. Writes (PATCH /{id}) require MFA-verified
# sessions because remediation state changes are accountable actions
# (control closure feeds the audit log + the eventual four-eyes
# approval check).
router = APIRouter(
    prefix="/remediation",
    tags=["remediation"],
    dependencies=[Depends(require_tenant_user)],
)


_NOT_IMPLEMENTED = {
    "detail": (
        "remediation API is not implemented yet — see "
        "api/src/routers/remediation.py for the implementation plan"
    ),
}


@router.get("")
async def list_items(
    hostname: str | None = None,
    status_filter: str | None = None,
    severity: str | None = None,
):
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=_NOT_IMPLEMENTED["detail"],
    )


@router.patch("/{item_id}", dependencies=[Depends(require_tenant_user_mfa)])
async def update_status(item_id: str):
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=_NOT_IMPLEMENTED["detail"],
    )
