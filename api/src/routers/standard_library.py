"""Browse-only API over the operator's frozen Rego policy library.

Authenticated (require_tenant_user) — every tenant sees the same
library, so this is read-only and tenant-agnostic. We still gate
behind login to keep the library private to paying tenants.

Not MFA-gated: browsing is read-only and doesn't write anything.
The fork endpoint (in policies router) IS write and uses
require_tenant_user_mfa.
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from ..core.sessions import require_tenant_user
from ..core.standard_library import (
    FileNotInLibrary,
    LibraryNotConfigured,
    categories,
    get_file,
    list_files,
    stats,
)
from ..models.standard_library import (
    LibraryStats,
    StandardFileContent,
    StandardFileMeta,
)


router = APIRouter(
    prefix="/portal/v1/standard-library",
    tags=["portal:standard-library"],
)


@router.get("/stats", response_model=LibraryStats)
async def get_stats(
    _: Annotated[dict[str, Any], Depends(require_tenant_user)],
) -> LibraryStats:
    try:
        s = stats()
    except LibraryNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return LibraryStats(**s)


@router.get("/categories", response_model=list[str])
async def get_categories(
    _: Annotated[dict[str, Any], Depends(require_tenant_user)],
) -> list[str]:
    try:
        return categories()
    except LibraryNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/files", response_model=list[StandardFileMeta])
async def get_files(
    _: Annotated[dict[str, Any], Depends(require_tenant_user)],
    prefix: str | None = Query(
        default=None,
        description="Filter files whose path starts with this prefix "
        "(e.g. 'benchmarks/cis/os/linux/rhel_9').",
    ),
    limit: int = Query(default=200, le=1000),
) -> list[StandardFileMeta]:
    try:
        files = list_files(prefix=prefix)
    except LibraryNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return [StandardFileMeta(**f.__dict__) for f in files[:limit]]


@router.get("/file", response_model=StandardFileContent)
async def get_file_content(
    _: Annotated[dict[str, Any], Depends(require_tenant_user)],
    path: str = Query(
        ...,
        description="Relative path under the library root. Use the same "
        "string the /files endpoint returns.",
    ),
) -> StandardFileContent:
    try:
        meta, text = get_file(path)
    except LibraryNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except FileNotInLibrary as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return StandardFileContent(rego_text=text, **meta.__dict__)
