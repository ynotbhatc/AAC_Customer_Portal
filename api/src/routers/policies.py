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
from ..core.ir_extractor import (
    InputTooLong,
    IrValidationError,
    extract_ir,
)
from ..core.llm_client import LlmError, get_llm_client
from ..core.portal_db import get_portal_pool
from ..core.rego_generator import GeneratedRego, generate_targets
from ..core.rego_validator import OpaBinaryMissing, OpaVersionTooOld
from ..core.sessions import require_tenant_user_mfa
from ..models.customer_policy import (
    CustomerPolicyDetail,
    CustomerPolicySummary,
    GeneratedTargetSummary,
    IRExtractionResponse,
    RegoGenerationResponse,
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


@router.post(
    "/{policy_id}/extract-ir",
    response_model=IRExtractionResponse,
    status_code=200,
)
async def extract_policy_ir(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
) -> IRExtractionResponse:
    """Run the LLM IR extractor against a draft customer_policies row.

    Reads the parsed text from policy_uploads via the policy's
    `source_file_storage_key`, calls the LLM under tool use, validates
    the structured response, writes it back to `customer_policies.ir_json`,
    and emits a policy_audit_log entry.

    Idempotent in effect: re-running on the same policy overwrites the
    previous IR. The deterministic source-offset ordering means the
    new vs old IR diff is readable in the review UI.
    """
    policy = await pool.fetchrow(
        """
        SELECT id, source_file_storage_key, policy_source
          FROM customer_policies
         WHERE id = $1 AND tenant_id = $2
        """,
        policy_id,
        tenant_user["tenant_id"],
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="policy not found")
    if policy["policy_source"] != "prose_upload":
        raise HTTPException(
            status_code=409,
            detail=f"IR extraction only applies to prose_upload "
            f"policies; this is {policy['policy_source']}",
        )
    key = policy["source_file_storage_key"]
    if not key or not key.startswith("pgupload:"):
        raise HTTPException(
            status_code=409,
            detail="policy has no extractable source in the MVP store",
        )
    upload_id = key.split(":", 1)[1]

    upload = await pool.fetchrow(
        """
        SELECT extracted_text FROM policy_uploads
         WHERE id = $1::uuid AND tenant_id = $2
        """,
        upload_id,
        tenant_user["tenant_id"],
    )
    if upload is None:
        raise HTTPException(status_code=500, detail="upload row missing")

    try:
        llm = get_llm_client()
    except LlmError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    try:
        ir = await extract_ir(parsed_text=upload["extracted_text"], llm=llm, pool=pool)
    except InputTooLong as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except IrValidationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except LlmError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    ir_dict = ir.model_dump(mode="json")
    matched = sum(1 for c in ir.controls if c.abstract_control_key is not None)
    freeform = len(ir.controls) - matched

    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE customer_policies
                   SET ir_json = $1::jsonb
                 WHERE id = $2 AND tenant_id = $3
                """,
                ir_dict,
                policy_id,
                tenant_user["tenant_id"],
            )
            await conn.execute(
                """
                INSERT INTO policy_audit_log
                    (tenant_id, tenant_user_id, customer_policy_id,
                     action, details)
                VALUES ($1, $2, $3, 'ir_extracted',
                        jsonb_build_object(
                            'model', $4::text,
                            'control_count', $5::int,
                            'controls_matched_library', $6::int,
                            'controls_freeform', $7::int,
                            'input_tokens', $8::int,
                            'output_tokens', $9::int))
                """,
                tenant_user["tenant_id"],
                tenant_user["tenant_user_id"],
                policy_id,
                ir.extraction_meta.model,
                len(ir.controls),
                matched,
                freeform,
                ir.extraction_meta.input_tokens,
                ir.extraction_meta.output_tokens,
            )

    return IRExtractionResponse(
        customer_policy_id=policy_id,
        schema_version=ir.schema_version,
        control_count=len(ir.controls),
        controls_matched_library=matched,
        controls_freeform=freeform,
        ir_json=ir_dict,
    )


@router.post(
    "/{policy_id}/generate-rego",
    response_model=RegoGenerationResponse,
    status_code=200,
)
async def generate_policy_rego(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
) -> RegoGenerationResponse:
    """Hybrid Rego generation.

    Reads the IR from `customer_policies.ir_json`, walks each control's
    applicability list, generates one Rego module per (control × target).
    Mappings present in `target_mappings` use Jinja templates from the
    library; misses fall through to the LLM with one bounded repair
    attempt.

    Re-running on the same policy: existing customer_policy_targets rows
    for the same (control, target_system) pair are replaced; the previous
    rego_storage_key is left in policy_uploads (the audit trail keeps
    the history of what was generated when).
    """
    policy = await pool.fetchrow(
        """
        SELECT id, name, effective_date, ir_json
          FROM customer_policies
         WHERE id = $1 AND tenant_id = $2
        """,
        policy_id,
        tenant_user["tenant_id"],
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="policy not found")
    if not policy["ir_json"]:
        raise HTTPException(
            status_code=409,
            detail="policy has no IR; call /extract-ir first",
        )

    try:
        llm = get_llm_client()
    except LlmError as exc:
        # Generation can still proceed for pure-template controls, but if
        # ANY control fans out to an unmapped target the request fails.
        # For Phase 2 we keep this simple: no LLM key → no generation.
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    s = get_settings()

    ir = policy["ir_json"]
    if isinstance(ir, str):
        # PostgreSQL JSONB → asyncpg returns a dict already, but defend
        # against the (unlikely) string roundtrip case.
        import json

        ir = json.loads(ir)

    all_generated: list[tuple[dict[str, Any], GeneratedRego]] = []
    try:
        for control in ir.get("controls", []):
            for gen in await generate_targets(
                pool=pool,
                tenant_id=str(tenant_user["tenant_id"]),
                policy_name=policy["name"],
                effective_date=(
                    policy["effective_date"].isoformat()
                    if policy["effective_date"]
                    else None
                ),
                ir_control=control,
                llm=llm,
            ):
                all_generated.append((control, gen))
    except (OpaBinaryMissing, OpaVersionTooOld) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except LlmError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    bundle_store = get_bundle_store()
    summaries: list[GeneratedTargetSummary] = []

    async with pool.acquire() as conn:
        async with conn.transaction():
            for control, gen in all_generated:
                control_key = control.get("abstract_control_key") or "freeform"
                filename = f"{control_key}__{gen.target_system}.rego"
                storage_key, _artifact_id = await bundle_store.put_rego(
                    tenant_id=tenant_user["tenant_id"],
                    uploaded_by_user_id=tenant_user["tenant_user_id"],
                    filename=filename,
                    rego_text=gen.rego_text,
                    conn=conn,
                )
                import hashlib

                sha = hashlib.sha256(gen.rego_text.encode("utf-8")).hexdigest()

                # Replace any prior target row for the same (policy, target,
                # subtype) tuple so re-runs are idempotent at the model layer.
                await conn.execute(
                    """
                    DELETE FROM customer_policy_targets
                     WHERE customer_policy_id = $1
                       AND target_system = $2
                       AND COALESCE(target_subtype, '') = COALESCE($3, '')
                    """,
                    policy_id,
                    gen.target_system,
                    gen.target_subtype,
                )
                row = await conn.fetchrow(
                    """
                    INSERT INTO customer_policy_targets
                        (customer_policy_id, target_system, target_subtype,
                         rego_storage_key, rego_content_sha256,
                         generation_method, confidence_score, review_status)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    RETURNING id
                    """,
                    policy_id,
                    gen.target_system,
                    gen.target_subtype,
                    storage_key,
                    sha,
                    gen.generation_method,
                    gen.confidence_score,
                    gen.review_status,
                )
                summaries.append(
                    GeneratedTargetSummary(
                        customer_policy_target_id=row["id"],
                        target_system=gen.target_system,
                        target_subtype=gen.target_subtype,
                        generation_method=gen.generation_method,
                        confidence_score=gen.confidence_score,
                        review_status=gen.review_status,
                        opa_check_ok=gen.opa_check_ok,
                        rego_storage_key=storage_key,
                        rego_content_sha256=sha,
                        llm_attempts=gen.llm_attempts,
                        model=gen.model,
                        opa_check_stderr=(
                            gen.opa_check_stderr
                            if gen.review_status == "rejected"
                            else None
                        ),
                    )
                )

            # Single audit-log line for the batch.
            await conn.execute(
                """
                INSERT INTO policy_audit_log
                    (tenant_id, tenant_user_id, customer_policy_id,
                     action, details)
                VALUES ($1, $2, $3, 'rego_generated',
                        jsonb_build_object(
                            'targets_generated', $4::int,
                            'targets_pending', $5::int,
                            'targets_rejected', $6::int,
                            'opa_version_floor',
                              format('%s.%s', $7::int, $8::int)))
                """,
                tenant_user["tenant_id"],
                tenant_user["tenant_user_id"],
                policy_id,
                len(summaries),
                sum(1 for s in summaries if s.review_status == "pending"),
                sum(1 for s in summaries if s.review_status == "rejected"),
                s.opa_min_version_major,
                s.opa_min_version_minor,
            )

    return RegoGenerationResponse(
        customer_policy_id=policy_id,
        targets_generated=len(summaries),
        targets_pending_review=sum(1 for s in summaries if s.review_status == "pending"),
        targets_rejected=sum(1 for s in summaries if s.review_status == "rejected"),
        targets=summaries,
    )
