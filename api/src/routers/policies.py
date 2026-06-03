"""Customer policy endpoints — Path A (prose upload) for now.

This PR's scope: accept a file, sniff its type, parse to plaintext,
store the bytes + extracted text, create a `customer_policies` row
in draft status. No LLM IR extraction yet (PR 6) and no Rego
generation (PR 7).

All write endpoints use `require_tenant_user_mfa` — uploading a
policy is a write that the audit log will reference, and a session
that hasn't verified the second factor must not be able to issue
those writes.
"""
from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

import asyncpg
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
)

from ..core.bundle_store import get_bundle_store
from ..core.config import get_settings
from ..core.document_parser import (
    EmptyExtraction,
    ParseTimeout,
    UnsupportedFormat,
    extract_text,
    sniff_mime,
)
from ..core.portal_db import get_portal_pool
from ..core.sessions import require_tenant_user_mfa
from ..models.customer_policy import (
    CustomerPolicyDetail,
    CustomerPolicySummary,
    UploadAccepted,
)


router = APIRouter(prefix="/portal/v1/me/policies", tags=["portal:policies"])


@router.post("/upload", response_model=UploadAccepted, status_code=201)
async def upload_policy(
    request: Request,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    name: Annotated[str, Form(min_length=1, max_length=255)],
    framework_bucket: Annotated[str, Form(min_length=1, max_length=128)],
    file: Annotated[UploadFile, File(...)],
) -> UploadAccepted:
    """Phase 2 Path A — accept a prose policy document, parse, store.

    Multipart form fields: `name`, `framework_bucket`, `file`.
    The file is read with a hard size cap; oversized uploads 413
    without ever loading the full payload into memory.
    """
    s = get_settings()

    # Cheap rejection — if Content-Length is set and over the cap,
    # don't even start reading.
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > s.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"upload exceeds {s.max_upload_bytes} bytes (declared {declared})",
        )

    # Read with an in-loop size guard. UploadFile.read() reads everything
    # into RAM; we read in chunks instead so an attacker can't bypass
    # the cap by lying about Content-Length.
    raw = bytearray()
    chunk_size = 64 * 1024
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        if len(raw) + len(chunk) > s.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"upload exceeds {s.max_upload_bytes} bytes",
            )
        raw.extend(chunk)
    raw_bytes = bytes(raw)
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="empty file")

    # Sniff MIME from the bytes — the client's Content-Type is advisory.
    try:
        mime = sniff_mime(raw_bytes, filename_hint=file.filename)
    except UnsupportedFormat as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc

    # Parse with a hard timeout to bound resource use against malicious docs.
    try:
        text = await extract_text(
            raw=raw_bytes, mime=mime, timeout_seconds=s.parser_timeout_seconds
        )
    except UnsupportedFormat as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except ParseTimeout as exc:
        raise HTTPException(status_code=408, detail=str(exc)) from exc
    except EmptyExtraction as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    bundle_store = get_bundle_store()

    # Atomicity: bytes row + customer_policies row + audit log line, one
    # transaction. Parsing already succeeded above (no DB held during it).
    async with pool.acquire() as conn:
        async with conn.transaction():
            storage_key, upload_id = await bundle_store.put(
                tenant_id=tenant_user["tenant_id"],
                uploaded_by_user_id=tenant_user["tenant_user_id"],
                filename=file.filename or "unnamed",
                sniffed_mime=mime,
                raw=raw_bytes,
                extracted_text=text,
                conn=conn,
            )

            policy_row = await conn.fetchrow(
                """
                INSERT INTO customer_policies
                    (tenant_id, name, framework_bucket, policy_source,
                     source_file_storage_key, source_file_mime,
                     created_by)
                VALUES ($1, $2, $3, 'prose_upload', $4, $5, $6)
                RETURNING id
                """,
                tenant_user["tenant_id"],
                name,
                framework_bucket,
                storage_key,
                mime,
                tenant_user["tenant_user_id"],
            )

            await conn.execute(
                """
                INSERT INTO policy_audit_log
                    (tenant_id, tenant_user_id, customer_policy_id,
                     action, details)
                VALUES ($1, $2, $3, 'uploaded',
                        jsonb_build_object(
                            'upload_id', $4::text,
                            'filename', $5::text,
                            'sniffed_mime', $6::text,
                            'byte_size', $7::int,
                            'extracted_chars', $8::int))
                """,
                tenant_user["tenant_id"],
                tenant_user["tenant_user_id"],
                policy_row["id"],
                str(upload_id),
                file.filename or "unnamed",
                mime,
                len(raw_bytes),
                len(text),
            )

    return UploadAccepted(
        customer_policy_id=policy_row["id"],
        upload_id=upload_id,
        original_filename=file.filename or "unnamed",
        sniffed_mime=mime,
        byte_size=len(raw_bytes),
        extracted_text_chars=len(text),
    )


@router.get("", response_model=list[CustomerPolicySummary])
async def list_policies(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    framework_bucket: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> list[dict]:
    conds = ["tenant_id = $1"]
    args: list = [tenant_user["tenant_id"]]
    if framework_bucket:
        args.append(framework_bucket)
        conds.append(f"framework_bucket = ${len(args)}")
    if status:
        args.append(status)
        conds.append(f"status = ${len(args)}")

    rows = await pool.fetch(
        f"""
        SELECT id, tenant_id, name, framework_bucket, policy_source,
               version_semver, effective_date, status, created_at, updated_at
          FROM customer_policies
         WHERE {" AND ".join(conds)}
         ORDER BY created_at DESC
        """,
        *args,
    )
    return [dict(r) for r in rows]


@router.get("/{policy_id}", response_model=CustomerPolicyDetail)
async def get_policy(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
) -> dict:
    row = await pool.fetchrow(
        """
        SELECT id, tenant_id, name, framework_bucket, policy_source,
               version_semver, effective_date, status, created_at, updated_at,
               source_file_storage_key, source_file_mime,
               parent_standard_ref, parent_standard_version, ir_json
          FROM customer_policies
         WHERE id = $1 AND tenant_id = $2
        """,
        policy_id,
        tenant_user["tenant_id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="policy not found")
    return dict(row)
