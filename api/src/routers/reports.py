"""Reports router — stub.

Frontend (frontend/src/lib/api.ts:downloadReport) calls:
    GET /api/reports/download?hostname&framework&format=pdf|csv|json

Returns 501 until the report generator lands. Plan in
docs/audit_reports_design.md (Phase 7).
"""
from fastapi import APIRouter, Depends, HTTPException, status

from ..core.sessions import require_tenant_user

router = APIRouter(
    prefix="/reports",
    tags=["reports"],
    dependencies=[Depends(require_tenant_user)],
)


@router.get("/download")
async def download(
    framework: str,
    hostname: str | None = None,
    format: str = "pdf",
):
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail=(
            "reports/download is not implemented yet — see "
            "docs/audit_reports_design.md for the spec"
        ),
    )
