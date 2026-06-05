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

import difflib
import hashlib
import json

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
from ..core.standard_library import (
    FileNotInLibrary,
    LibraryNotConfigured,
    get_file as std_get_file,
)

from ..models.customer_policy import (
    CustomerPolicyDetail,
    CustomerPolicySummary,
    GeneratedTargetSummary,
    IRExtractionResponse,
    RegoGenerationResponse,
    RepublishRequest,
    RepublishResponse,
    UploadAccepted,
)
from ..models.policy_audit import AuditLogEntry
from ..models.standard_library import ForkRequest, ForkResponse, UpstreamDiff
from ..models.target_review import (
    TargetDetail,
    TargetEditRequest,
    TargetReviewAction,
    TargetSummary,
)
from ..core.rego_validator import opa_check


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


@router.post(
    "/{policy_id}/publish",
    response_model=None,
    status_code=200,
)
async def publish_policy(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
):
    """Flip a policy from draft/in_review to published.

    Requires:
      - status != 'published' (re-publish goes through the republish
        flow, which is a new customer_policies row in PR 9b)
      - at least one customer_policy_targets row with
        review_status='approved'

    The trigger from migration 012 enforces post-publish immutability:
    in-place edits raise CHECK violation. A subsequent build endpoint
    folds this policy's approved targets into the next bundle.
    """
    from ..models.policy_bundle import PublishResponse

    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT id, status, version_semver
                  FROM customer_policies
                 WHERE id = $1 AND tenant_id = $2
                 FOR UPDATE
                """,
                policy_id,
                tenant_user["tenant_id"],
            )
            if row is None:
                raise HTTPException(status_code=404, detail="policy not found")
            if row["status"] == "published":
                raise HTTPException(
                    status_code=409,
                    detail="policy is already published; create a new version "
                    "to republish",
                )

            approved = await conn.fetchval(
                """
                SELECT COUNT(*) FROM customer_policy_targets
                 WHERE customer_policy_id = $1
                   AND review_status = 'approved'
                """,
                policy_id,
            )
            if approved == 0:
                raise HTTPException(
                    status_code=409,
                    detail="no approved targets — review at least one target "
                    "before publishing",
                )

            updated = await conn.fetchrow(
                """
                UPDATE customer_policies
                   SET status = 'published',
                       published_at = now(),
                       published_by = $2
                 WHERE id = $1
                RETURNING id, status, published_at, version_semver
                """,
                policy_id,
                tenant_user["tenant_user_id"],
            )

            await conn.execute(
                """
                INSERT INTO policy_audit_log
                    (tenant_id, tenant_user_id, customer_policy_id,
                     action, details)
                VALUES ($1, $2, $3, 'published',
                        jsonb_build_object(
                            'approved_targets', $4::int,
                            'version_semver', $5::text))
                """,
                tenant_user["tenant_id"],
                tenant_user["tenant_user_id"],
                policy_id,
                approved,
                row["version_semver"],
            )

    return PublishResponse(
        customer_policy_id=updated["id"],
        status=updated["status"],
        published_at=updated["published_at"],
        version_semver=updated["version_semver"],
    )


# ── Path B — fork-and-tweak ───────────────────────────────────────────


_TARGET_SYSTEM_HINTS = (
    ("linux", "linux"),
    ("windows", "windows"),
    ("kubernetes", "kubernetes"),
    ("rhel", "linux"),
    ("ubuntu", "linux"),
    ("debian", "linux"),
    ("docker", "linux"),
    ("aws", "aws"),
    ("azure", "azure"),
    ("gcp", "gcp"),
    ("m365", "m365"),
)


def _infer_target_system(path: str) -> str:
    """Best-effort heuristic — path segments often name the platform.
    Returns 'unknown' if nothing matches; UI can prompt the customer
    to pick a target explicitly."""
    lower = path.lower()
    for needle, system in _TARGET_SYSTEM_HINTS:
        if needle in lower:
            return system
    return "unknown"


@router.post(
    "/fork",
    response_model=ForkResponse,
    status_code=201,
)
async def fork_standard_policy(
    body: ForkRequest,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> ForkResponse:
    """Create a customer overlay by snapshotting a standard library file.

    The fork is exact at this point — overlay content == upstream
    content. The customer edits via a future PATCH endpoint; until
    then, GET /upstream-diff returns an empty diff. parent_standard_ref
    + parent_standard_version stamp the upstream baseline so drift
    detection (PR 11+) can flag when the library moves ahead.
    """
    try:
        meta, rego_text = std_get_file(body.standard_library_path)
    except LibraryNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except FileNotInLibrary as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    s = get_settings()
    target_system = _infer_target_system(body.standard_library_path)
    bundle_store = get_bundle_store()
    fork_sha = hashlib.sha256(rego_text.encode("utf-8")).hexdigest()

    async with pool.acquire() as conn:
        async with conn.transaction():
            policy_row = await conn.fetchrow(
                """
                INSERT INTO customer_policies
                    (tenant_id, name, framework_bucket, policy_source,
                     parent_standard_ref, parent_standard_version,
                     created_by)
                VALUES ($1, $2, $3, 'forked_overlay', $4, $5, $6)
                RETURNING id
                """,
                tenant_user["tenant_id"],
                body.name,
                body.framework_bucket,
                body.standard_library_path,
                s.standard_library_version,
                tenant_user["tenant_user_id"],
            )

            storage_key, _artifact_id = await bundle_store.put_rego(
                tenant_id=tenant_user["tenant_id"],
                uploaded_by_user_id=tenant_user["tenant_user_id"],
                filename=f"fork__{body.standard_library_path.replace('/', '__')}",
                rego_text=rego_text,
                conn=conn,
            )

            target_row = await conn.fetchrow(
                """
                INSERT INTO customer_policy_targets
                    (customer_policy_id, target_system, rego_storage_key,
                     rego_content_sha256, generation_method, review_status)
                VALUES ($1, $2, $3, $4, 'customer_authored', 'pending')
                RETURNING id
                """,
                policy_row["id"],
                target_system,
                storage_key,
                fork_sha,
            )

            await conn.execute(
                """
                INSERT INTO policy_audit_log
                    (tenant_id, tenant_user_id, customer_policy_id,
                     action, details)
                VALUES ($1, $2, $3, 'forked',
                        jsonb_build_object(
                            'parent_standard_ref', $4::text,
                            'parent_standard_version', $5::text,
                            'fork_sha256', $6::text,
                            'target_system', $7::text))
                """,
                tenant_user["tenant_id"],
                tenant_user["tenant_user_id"],
                policy_row["id"],
                body.standard_library_path,
                s.standard_library_version,
                fork_sha,
                target_system,
            )

    return ForkResponse(
        customer_policy_id=policy_row["id"],
        customer_policy_target_id=target_row["id"],
        parent_standard_ref=body.standard_library_path,
        parent_standard_version=s.standard_library_version,
        target_system=target_system,
    )


@router.get(
    "/{policy_id}/upstream-diff",
    response_model=UpstreamDiff,
)
async def get_upstream_diff(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
) -> UpstreamDiff:
    """Return a unified diff between the customer's current overlay
    and the current standard library content of the file they forked.

    If upstream hasn't moved since the fork, `upstream_changed_since_fork`
    is false and the diff reflects only the customer's edits.
    """
    policy = await pool.fetchrow(
        """
        SELECT cp.id, cp.policy_source,
               cp.parent_standard_ref,
               cp.parent_standard_version,
               cpt.rego_storage_key,
               cpt.rego_content_sha256
          FROM customer_policies cp
          LEFT JOIN LATERAL (
            SELECT rego_storage_key, rego_content_sha256
              FROM customer_policy_targets
             WHERE customer_policy_id = cp.id
             ORDER BY created_at DESC
             LIMIT 1
          ) cpt ON true
         WHERE cp.id = $1 AND cp.tenant_id = $2
        """,
        policy_id,
        tenant_user["tenant_id"],
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="policy not found")
    if policy["policy_source"] != "forked_overlay":
        raise HTTPException(
            status_code=409,
            detail=f"upstream-diff only applies to forked_overlay "
            f"policies; this is {policy['policy_source']}",
        )
    if not policy["parent_standard_ref"]:
        raise HTTPException(status_code=500, detail="forked policy missing parent_standard_ref")

    # Current upstream
    try:
        upstream_meta, upstream_text = std_get_file(policy["parent_standard_ref"])
    except LibraryNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except FileNotInLibrary as exc:
        raise HTTPException(
            status_code=404,
            detail=f"upstream file gone from current library: {exc!s}",
        ) from exc

    # Customer overlay
    key = policy["rego_storage_key"]
    if not key or not key.startswith("pgrego:"):
        raise HTTPException(status_code=500, detail="overlay missing in pg store")
    artifact_id = key.split(":", 1)[1]
    overlay_row = await pool.fetchrow(
        "SELECT extracted_text FROM policy_uploads WHERE id = $1::uuid",
        artifact_id,
    )
    if overlay_row is None:
        raise HTTPException(status_code=500, detail="overlay row missing")
    overlay_text = overlay_row["extracted_text"]
    overlay_sha = hashlib.sha256(overlay_text.encode("utf-8")).hexdigest()

    diff_lines = difflib.unified_diff(
        upstream_text.splitlines(keepends=True),
        overlay_text.splitlines(keepends=True),
        fromfile=f"upstream/{policy['parent_standard_ref']}",
        tofile=f"overlay/{policy['parent_standard_ref']}",
        n=3,
    )

    s = get_settings()

    return UpstreamDiff(
        customer_policy_id=policy["id"],
        parent_standard_ref=policy["parent_standard_ref"],
        parent_standard_version=policy["parent_standard_version"],
        current_upstream_sha256=upstream_meta.sha256,
        fork_sha256=policy["rego_content_sha256"],
        overlay_sha256=overlay_sha,
        upstream_changed_since_fork=(
            policy["parent_standard_version"] != s.standard_library_version
        ),
        unified_diff="".join(diff_lines),
    )


# ── Target review workflow ────────────────────────────────────────────


async def _fetch_policy_for_target_action(
    pool: asyncpg.Pool,
    tenant_id: UUID,
    policy_id: UUID,
) -> dict[str, Any]:
    """Look up the parent policy + assert tenant ownership + status.

    Any mutating target action (PATCH / approve / reject) requires the
    parent customer_policy to NOT be published. Once a policy is
    published, its targets are frozen — editing them would mutate
    what shipped in the bundle. Republish via a new customer_policies
    row is the only path forward.
    """
    row = await pool.fetchrow(
        "SELECT id, status FROM customer_policies WHERE id = $1 AND tenant_id = $2",
        policy_id,
        tenant_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="policy not found")
    if row["status"] == "published":
        raise HTTPException(
            status_code=409,
            detail="parent policy is published; republish via a new "
            "version to edit targets",
        )
    return dict(row)


@router.get(
    "/{policy_id}/targets",
    response_model=list[TargetSummary],
)
async def list_policy_targets(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
) -> list[dict]:
    # Verify the policy belongs to this tenant; raises 404 if not.
    policy = await pool.fetchrow(
        "SELECT id FROM customer_policies WHERE id = $1 AND tenant_id = $2",
        policy_id,
        tenant_user["tenant_id"],
    )
    if policy is None:
        raise HTTPException(status_code=404, detail="policy not found")

    rows = await pool.fetch(
        """
        SELECT id, customer_policy_id, target_system, target_subtype,
               generation_method, confidence_score, review_status,
               rego_content_sha256, published_in_bundle_sha, created_at
          FROM customer_policy_targets
         WHERE customer_policy_id = $1
         ORDER BY target_system, target_subtype NULLS FIRST, created_at DESC
        """,
        policy_id,
    )
    return [dict(r) for r in rows]


@router.get(
    "/{policy_id}/targets/{target_id}",
    response_model=TargetDetail,
)
async def get_policy_target(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
    target_id: UUID,
) -> dict:
    row = await pool.fetchrow(
        """
        SELECT cpt.id, cpt.customer_policy_id, cpt.target_system,
               cpt.target_subtype, cpt.generation_method,
               cpt.confidence_score, cpt.review_status,
               cpt.rego_content_sha256, cpt.published_in_bundle_sha,
               cpt.created_at, cpt.rego_storage_key
          FROM customer_policy_targets cpt
          JOIN customer_policies cp ON cp.id = cpt.customer_policy_id
         WHERE cpt.id = $1
           AND cp.id = $2
           AND cp.tenant_id = $3
        """,
        target_id,
        policy_id,
        tenant_user["tenant_id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="target not found")

    key = row["rego_storage_key"]
    if not key or not key.startswith("pgrego:"):
        raise HTTPException(status_code=500, detail="rego artifact key missing or unsupported")
    artifact_id = key.split(":", 1)[1]
    artifact = await pool.fetchrow(
        "SELECT extracted_text FROM policy_uploads WHERE id = $1::uuid",
        artifact_id,
    )
    if artifact is None:
        raise HTTPException(status_code=500, detail="rego artifact row missing")

    return {**dict(row), "rego_text": artifact["extracted_text"]}


@router.patch(
    "/{policy_id}/targets/{target_id}",
    response_model=TargetDetail,
)
async def edit_policy_target(
    body: TargetEditRequest,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
    target_id: UUID,
) -> dict:
    """Replace a target's Rego text. Re-validates via `opa check`.

    A successful edit resets review_status to 'pending' regardless of
    what it was — the customer must re-review the modified Rego
    before it can ship in a bundle. published_in_bundle_sha is left
    intact for the audit trail (it points at the historical bundle
    the prior version shipped in, if any).

    A failed `opa check` 422s with stderr in the response so the UI
    can show the customer what to fix. No DB write happens on failure.
    """
    await _fetch_policy_for_target_action(
        pool, tenant_user["tenant_id"], policy_id
    )

    existing = await pool.fetchrow(
        """
        SELECT cpt.id, cpt.target_system, cpt.target_subtype,
               cpt.review_status, cpt.rego_content_sha256
          FROM customer_policy_targets cpt
          JOIN customer_policies cp ON cp.id = cpt.customer_policy_id
         WHERE cpt.id = $1 AND cp.id = $2 AND cp.tenant_id = $3
        """,
        target_id,
        policy_id,
        tenant_user["tenant_id"],
    )
    if existing is None:
        raise HTTPException(status_code=404, detail="target not found")

    try:
        check = await opa_check(rego_text=body.rego_text)
    except (OpaBinaryMissing, OpaVersionTooOld) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not check.ok:
        raise HTTPException(
            status_code=422,
            detail={"reason": "opa_check failed", "stderr": check.stderr[:2000]},
        )

    new_sha = hashlib.sha256(body.rego_text.encode("utf-8")).hexdigest()
    bundle_store = get_bundle_store()

    async with pool.acquire() as conn:
        async with conn.transaction():
            storage_key, _artifact_id = await bundle_store.put_rego(
                tenant_id=tenant_user["tenant_id"],
                uploaded_by_user_id=tenant_user["tenant_user_id"],
                filename=f"edit__{existing['target_system']}__{new_sha[:8]}.rego",
                rego_text=body.rego_text,
                conn=conn,
            )

            updated = await conn.fetchrow(
                """
                UPDATE customer_policy_targets
                   SET rego_storage_key = $1,
                       rego_content_sha256 = $2,
                       review_status = 'pending'
                 WHERE id = $3
                RETURNING id, customer_policy_id, target_system,
                          target_subtype, generation_method,
                          confidence_score, review_status,
                          rego_content_sha256, published_in_bundle_sha,
                          created_at, rego_storage_key
                """,
                storage_key,
                new_sha,
                target_id,
            )

            await conn.execute(
                """
                INSERT INTO policy_audit_log
                    (tenant_id, tenant_user_id, customer_policy_id,
                     action, details)
                VALUES ($1, $2, $3, 'target_edited',
                        jsonb_build_object(
                            'target_id', $4::text,
                            'prior_review_status', $5::text,
                            'prior_sha256', $6::text,
                            'new_sha256', $7::text))
                """,
                tenant_user["tenant_id"],
                tenant_user["tenant_user_id"],
                policy_id,
                str(target_id),
                existing["review_status"],
                existing["rego_content_sha256"],
                new_sha,
            )

    return {**dict(updated), "rego_text": body.rego_text}


@router.post(
    "/{policy_id}/targets/{target_id}/approve",
    response_model=TargetSummary,
)
async def approve_policy_target(
    body: TargetReviewAction,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
    target_id: UUID,
) -> dict:
    """Mark a target as approved — eligible to ship in the next bundle.

    Reject → approve directly is permitted: the customer might have
    rejected, edited (which resets to pending), then approved. We
    don't gate approve on prior status to keep the workflow flexible.
    """
    await _fetch_policy_for_target_action(
        pool, tenant_user["tenant_id"], policy_id
    )

    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                UPDATE customer_policy_targets cpt
                   SET review_status = 'approved'
                  FROM customer_policies cp
                 WHERE cpt.id = $1
                   AND cp.id = cpt.customer_policy_id
                   AND cp.id = $2
                   AND cp.tenant_id = $3
                RETURNING cpt.id, cpt.customer_policy_id, cpt.target_system,
                          cpt.target_subtype, cpt.generation_method,
                          cpt.confidence_score, cpt.review_status,
                          cpt.rego_content_sha256,
                          cpt.published_in_bundle_sha, cpt.created_at
                """,
                target_id,
                policy_id,
                tenant_user["tenant_id"],
            )
            if row is None:
                raise HTTPException(status_code=404, detail="target not found")

            await conn.execute(
                """
                INSERT INTO policy_audit_log
                    (tenant_id, tenant_user_id, customer_policy_id,
                     action, details)
                VALUES ($1, $2, $3, 'target_approved',
                        jsonb_build_object(
                            'target_id', $4::text,
                            'sha256', $5::text,
                            'reason', $6::text))
                """,
                tenant_user["tenant_id"],
                tenant_user["tenant_user_id"],
                policy_id,
                str(target_id),
                row["rego_content_sha256"],
                body.reason,
            )

    return dict(row)


@router.post(
    "/{policy_id}/targets/{target_id}/reject",
    response_model=TargetSummary,
)
async def reject_policy_target(
    body: TargetReviewAction,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
    target_id: UUID,
) -> dict:
    """Mark a target rejected. Reason is required — the audit log
    needs to record WHY a generated Rego didn't pass review, so a
    future reviewer / auditor can understand the decision."""
    if not body.reason or not body.reason.strip():
        raise HTTPException(
            status_code=400,
            detail="rejection reason is required",
        )

    await _fetch_policy_for_target_action(
        pool, tenant_user["tenant_id"], policy_id
    )

    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                UPDATE customer_policy_targets cpt
                   SET review_status = 'rejected'
                  FROM customer_policies cp
                 WHERE cpt.id = $1
                   AND cp.id = cpt.customer_policy_id
                   AND cp.id = $2
                   AND cp.tenant_id = $3
                RETURNING cpt.id, cpt.customer_policy_id, cpt.target_system,
                          cpt.target_subtype, cpt.generation_method,
                          cpt.confidence_score, cpt.review_status,
                          cpt.rego_content_sha256,
                          cpt.published_in_bundle_sha, cpt.created_at
                """,
                target_id,
                policy_id,
                tenant_user["tenant_id"],
            )
            if row is None:
                raise HTTPException(status_code=404, detail="target not found")

            await conn.execute(
                """
                INSERT INTO policy_audit_log
                    (tenant_id, tenant_user_id, customer_policy_id,
                     action, details)
                VALUES ($1, $2, $3, 'target_rejected',
                        jsonb_build_object(
                            'target_id', $4::text,
                            'sha256', $5::text,
                            'reason', $6::text))
                """,
                tenant_user["tenant_id"],
                tenant_user["tenant_user_id"],
                policy_id,
                str(target_id),
                row["rego_content_sha256"],
                body.reason,
            )

    return dict(row)


# ── Republish flow ────────────────────────────────────────────────────


from ..core.semver_util import bump_patch as _bump_patch  # noqa: E402


@router.post(
    "/{policy_id}/republish",
    response_model=RepublishResponse,
    status_code=201,
)
async def republish_policy(
    body: RepublishRequest,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
) -> RepublishResponse:
    """Create a draft successor to a published policy.

    The new row inherits every content field (name, framework_bucket,
    policy_source, IR JSON, source storage key, parent_standard_*),
    bumps version_semver, and starts in status='draft'. Existing
    customer_policy_targets rows are copied 1:1 with their rego
    artifacts and review_status preserved — same Rego content means
    the prior review verdict still applies.

    The original published policy is left untouched (the immutability
    trigger guarantees that). Customers can then edit / approve /
    publish the new draft like any other.
    """
    parent = await pool.fetchrow(
        """
        SELECT id, name, framework_bucket, policy_source, version_semver,
               status, ir_json, source_file_storage_key, source_file_mime,
               parent_standard_ref, parent_standard_version,
               control_owner_user_id, review_cadence_days
          FROM customer_policies
         WHERE id = $1 AND tenant_id = $2
        """,
        policy_id,
        tenant_user["tenant_id"],
    )
    if parent is None:
        raise HTTPException(status_code=404, detail="policy not found")
    if parent["status"] != "published":
        raise HTTPException(
            status_code=409,
            detail=f"republish only applies to published policies; "
            f"this is {parent['status']}. Edit the draft directly.",
        )

    if body.new_version_semver:
        new_version = body.new_version_semver.strip()
    else:
        new_version = _bump_patch(parent["version_semver"])
        if new_version is None:
            raise HTTPException(
                status_code=400,
                detail=f"parent version_semver={parent['version_semver']!r} "
                "doesn't match vMAJ.MIN.PATCH; supply new_version_semver "
                "explicitly",
            )

    collision = await pool.fetchval(
        """
        SELECT 1 FROM customer_policies
         WHERE tenant_id = $1 AND name = $2 AND version_semver = $3
        """,
        tenant_user["tenant_id"],
        parent["name"],
        new_version,
    )
    if collision:
        raise HTTPException(
            status_code=409,
            detail=f"version {new_version!r} already exists for this policy "
            f"name; pick a higher version",
        )

    async with pool.acquire() as conn:
        async with conn.transaction():
            new_policy = await conn.fetchrow(
                """
                INSERT INTO customer_policies
                    (tenant_id, name, framework_bucket, policy_source,
                     source_file_storage_key, source_file_mime, ir_json,
                     parent_standard_ref, parent_standard_version,
                     version_semver, status,
                     control_owner_user_id, review_cadence_days,
                     created_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'draft',
                        $11, $12, $13)
                RETURNING id
                """,
                tenant_user["tenant_id"],
                parent["name"],
                parent["framework_bucket"],
                parent["policy_source"],
                parent["source_file_storage_key"],
                parent["source_file_mime"],
                parent["ir_json"],
                parent["parent_standard_ref"],
                parent["parent_standard_version"],
                new_version,
                parent["control_owner_user_id"],
                parent["review_cadence_days"],
                tenant_user["tenant_user_id"],
            )

            # Copy targets 1:1. published_in_bundle_sha is NOT carried
            # forward — the new policy hasn't shipped yet. The Rego
            # artifact (pgrego key) is shared with the parent; both
            # rows point at the same policy_uploads row. Customers
            # who PATCH a target post-republish create a new artifact
            # row, leaving the parent's reference intact.
            target_copies = await conn.fetch(
                """
                INSERT INTO customer_policy_targets
                    (customer_policy_id, target_system, target_subtype,
                     rego_storage_key, rego_content_sha256,
                     generation_method, confidence_score, review_status)
                SELECT $1, target_system, target_subtype,
                       rego_storage_key, rego_content_sha256,
                       generation_method, confidence_score, review_status
                  FROM customer_policy_targets
                 WHERE customer_policy_id = $2
                RETURNING id
                """,
                new_policy["id"],
                policy_id,
            )

            await conn.execute(
                """
                INSERT INTO policy_audit_log
                    (tenant_id, tenant_user_id, customer_policy_id,
                     action, details)
                VALUES ($1, $2, $3, 'republished_from',
                        jsonb_build_object(
                            'parent_policy_id', $4::text,
                            'parent_version_semver', $5::text,
                            'new_version_semver', $6::text,
                            'targets_copied', $7::int))
                """,
                tenant_user["tenant_id"],
                tenant_user["tenant_user_id"],
                new_policy["id"],
                str(policy_id),
                parent["version_semver"],
                new_version,
                len(target_copies),
            )

    return RepublishResponse(
        new_customer_policy_id=new_policy["id"],
        new_version_semver=new_version,
        targets_copied=len(target_copies),
        parent_policy_id=policy_id,
        parent_version_semver=parent["version_semver"],
    )


# ── Audit log read endpoint ───────────────────────────────────────────


@router.get(
    "/{policy_id}/audit-log",
    response_model=list[AuditLogEntry],
)
async def list_policy_audit_log(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    policy_id: UUID,
    limit: int = Query(50, ge=1, le=200),
    before_id: int | None = Query(
        None,
        description="Cursor — return entries with id < before_id. "
        "Use the smallest id from the prior page.",
    ),
) -> list[dict]:
    """Reverse-chronological audit log for one policy.

    The append-only `policy_audit_log` table records every state change
    (upload, ir_extracted, rego_generated, target_approved/rejected/
    edited, published, target_copied_on_republish, ...). This endpoint
    is the customer-facing read view; it is tenant-scoped and joins
    `tenant_users` to surface the actor's email.

    Pagination is cursor-based on `id` because `at` is not unique. The
    caller pages backwards by passing the smallest `id` from the
    previous response as `before_id`.
    """
    # Verify the policy belongs to this tenant; raises 404 if not.
    owned = await pool.fetchval(
        "SELECT 1 FROM customer_policies WHERE id = $1 AND tenant_id = $2",
        policy_id,
        tenant_user["tenant_id"],
    )
    if owned is None:
        raise HTTPException(status_code=404, detail="policy not found")

    if before_id is None:
        rows = await pool.fetch(
            """
            SELECT pal.id, pal.action, pal.details, pal.at,
                   pal.tenant_user_id, tu.email AS actor_email
              FROM policy_audit_log pal
              LEFT JOIN tenant_users tu ON tu.id = pal.tenant_user_id
             WHERE pal.customer_policy_id = $1
             ORDER BY pal.id DESC
             LIMIT $2
            """,
            policy_id,
            limit,
        )
    else:
        rows = await pool.fetch(
            """
            SELECT pal.id, pal.action, pal.details, pal.at,
                   pal.tenant_user_id, tu.email AS actor_email
              FROM policy_audit_log pal
              LEFT JOIN tenant_users tu ON tu.id = pal.tenant_user_id
             WHERE pal.customer_policy_id = $1
               AND pal.id < $2
             ORDER BY pal.id DESC
             LIMIT $3
            """,
            policy_id,
            before_id,
            limit,
        )

    return [
        {
            "id": r["id"],
            "action": r["action"],
            "details": r["details"] if isinstance(r["details"], dict)
            else (json.loads(r["details"]) if r["details"] else {}),
            "at": r["at"],
            "tenant_user_id": str(r["tenant_user_id"])
            if r["tenant_user_id"] is not None
            else None,
            "actor_email": r["actor_email"],
        }
        for r in rows
    ]
