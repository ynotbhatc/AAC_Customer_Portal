"""Customer policy bundle endpoints.

Two auth surfaces:

  Tenant-USER (MFA session) — POST .../bundles/build, GET .../bundles/manifest
      These are interactive operations the portal UI calls.

  Tenant-TOKEN (M2M bridge scope=policy_bundle_pull) —
      GET /api/portal/v1/tenants/{tenant_id}/bundles/current
      GET /api/portal/v1/tenants/{tenant_id}/bundles/{sha256}
      GET /api/portal/v1/tenants/{tenant_id}/bundles/{sha256}/envelope
      These are what the AAC bridge polls. Tokens are issued by the
      operator via the existing tenants admin router; this PR adds the
      'policy_bundle_pull' scope name as a contract.

  PUBLIC (no auth):
      GET /api/portal/v1/bundles/signing-key — bridge bootstrap.
"""
from __future__ import annotations

import json
from typing import Annotated, Any
from uuid import UUID


def _ensure_json(value: Any) -> Any:
    """Asyncpg returns jsonb as raw JSON text str unless a connection
    codec is registered. Defend at the call site — matches the pattern
    already used in policies.py for `ir_json`. Idempotent: if asyncpg
    DOES return a dict/list, this is a no-op.
    """
    return json.loads(value) if isinstance(value, str) else value

import asyncpg
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response

from ..core.audit_actions import AuditAction
from ..core.bundle_builder import build_tenant_bundle
from ..core.bundle_signer import (
    SigningKeyMissing,
    public_key_b64,
    sign_bundle,
)
from ..core.config import get_settings
from ..core.portal_db import get_portal_pool
from ..core.rego_validator import OpaBinaryMissing, OpaVersionTooOld
from ..core.sessions import require_tenant_user_mfa
from ..core.tenant_auth import BUNDLE_PULL_SCOPE, require_tenant_with_scope
from ..models.policy_bundle import (
    BuildBundleResponse,
    BundleHistoryEntry,
    BundleManifest,
    SigningKeyInfo,
)


# ── User-facing build + manifest endpoints ─────────────────────────────


user_router = APIRouter(prefix="/portal/v1/me/bundles", tags=["portal:bundles"])


@user_router.post("/build", response_model=BuildBundleResponse, status_code=201)
async def build_bundle(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> BuildBundleResponse:
    """Build a fresh tenant bundle from all published+approved targets.

    Idempotent in effect: the same approved set produces the same
    bundle bytes (modulo opa build's internal ordering). Each call
    inserts a new row; the most recent row is "current."
    """
    try:
        result = await build_tenant_bundle(
            pool=pool, tenant_id=str(tenant_user["tenant_id"])
        )
    except (OpaBinaryMissing, OpaVersionTooOld) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    try:
        envelope = sign_bundle(
            tenant_id=str(tenant_user["tenant_id"]),
            bundle_sha256=result.bundle_sha256,
            bundle_byte_size=len(result.bundle_bytes),
            target_count=result.target_count,
            customer_policy_ids=result.customer_policy_ids,
        )
    except SigningKeyMissing as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    s = get_settings()

    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                INSERT INTO policy_bundles
                    (tenant_id, bundle_sha256, bundle_bytes,
                     bundle_byte_size, signed_envelope_bytes,
                     signing_key_id, manifest, target_count,
                     customer_policy_ids, excluded_target_count,
                     excluded_targets_log, built_by_user_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10, $11::jsonb, $12)
                RETURNING id, built_at
                """,
                tenant_user["tenant_id"],
                result.bundle_sha256,
                result.bundle_bytes,
                len(result.bundle_bytes),
                envelope,
                s.bundle_signing_key_id,
                json.dumps(result.manifest),
                result.target_count,
                [UUID(p) for p in result.customer_policy_ids],
                len(result.excluded_targets),
                json.dumps(result.excluded_targets),
                tenant_user["tenant_user_id"],
            )

            # Stamp each published target with the bundle sha so audit can
            # answer "what was in the bundle that shipped on date Y."
            await conn.execute(
                """
                UPDATE customer_policy_targets cpt
                   SET published_in_bundle_sha = $2
                  FROM customer_policies cp
                 WHERE cpt.customer_policy_id = cp.id
                   AND cp.tenant_id = $1
                   AND cp.status = 'published'
                   AND cpt.review_status = 'approved'
                """,
                tenant_user["tenant_id"],
                result.bundle_sha256,
            )

            await conn.execute(
                f"""
                INSERT INTO policy_audit_log
                    (tenant_id, tenant_user_id, action, details)
                VALUES ($1, $2, '{AuditAction.BUNDLE_BUILT.value}',
                        jsonb_build_object(
                            'bundle_sha256', $3::text,
                            'target_count',  $4::int,
                            'excluded',      $5::int,
                            'signing_key_id', $6::text))
                """,
                tenant_user["tenant_id"],
                tenant_user["tenant_user_id"],
                result.bundle_sha256,
                result.target_count,
                len(result.excluded_targets),
                s.bundle_signing_key_id,
            )

    return BuildBundleResponse(
        bundle_id=row["id"],
        bundle_sha256=result.bundle_sha256,
        bundle_byte_size=len(result.bundle_bytes),
        target_count=result.target_count,
        excluded_target_count=len(result.excluded_targets),
        customer_policy_ids=[UUID(p) for p in result.customer_policy_ids],
        built_at=row["built_at"],
        signing_key_id=s.bundle_signing_key_id,
    )


# ── Bridge-facing pull endpoints (tenant-token, M2M) ───────────────────


bridge_router = APIRouter(
    prefix="/portal/v1/tenants/{tenant_id}/bundles",
    tags=["bridge:bundles"],
)

_bridge_dep = require_tenant_with_scope(BUNDLE_PULL_SCOPE)


@bridge_router.get("/current")
async def bridge_get_current_bundle(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant: Annotated[dict[str, Any], Depends(_bridge_dep)],
    tenant_id: UUID = Path(...),
) -> Response:
    """Return the most recent bundle's raw bytes (application/gzip).
    The signed envelope is delivered separately via /envelope so the
    bridge can fetch them independently for caching."""
    row = await pool.fetchrow(
        """
        SELECT bundle_bytes, bundle_sha256, signing_key_id
          FROM policy_bundles
         WHERE tenant_id = $1
         ORDER BY built_at DESC
         LIMIT 1
        """,
        tenant_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="no bundle built yet")
    return Response(
        content=row["bundle_bytes"],
        media_type="application/gzip",
        headers={
            "X-Bundle-SHA256": row["bundle_sha256"],
            "X-Signing-Key-Id": row["signing_key_id"],
        },
    )


@bridge_router.get("/current/envelope")
async def bridge_get_current_envelope(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant: Annotated[dict[str, Any], Depends(_bridge_dep)],
    tenant_id: UUID = Path(...),
) -> Response:
    row = await pool.fetchrow(
        """
        SELECT signed_envelope_bytes
          FROM policy_bundles
         WHERE tenant_id = $1
         ORDER BY built_at DESC
         LIMIT 1
        """,
        tenant_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="no bundle built yet")
    return Response(
        content=row["signed_envelope_bytes"],
        media_type="application/jose+json",
    )


@bridge_router.get("/{bundle_sha256}")
async def bridge_get_bundle_by_sha(
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    tenant: Annotated[dict[str, Any], Depends(_bridge_dep)],
    tenant_id: UUID = Path(...),
    bundle_sha256: str = Path(..., min_length=64, max_length=64),
) -> Response:
    """Rollback support — fetch a historical bundle by its SHA256."""
    row = await pool.fetchrow(
        """
        SELECT bundle_bytes, signing_key_id
          FROM policy_bundles
         WHERE tenant_id = $1 AND bundle_sha256 = $2
        """,
        tenant_id,
        bundle_sha256,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="bundle sha not found for tenant")
    return Response(
        content=row["bundle_bytes"],
        media_type="application/gzip",
        headers={
            "X-Bundle-SHA256": bundle_sha256,
            "X-Signing-Key-Id": row["signing_key_id"],
        },
    )


# ── Manifest (current bundle, MFA session) ─────────────────────────────


@user_router.get("/current/manifest", response_model=BundleManifest)
async def get_current_manifest(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> BundleManifest:
    row = await pool.fetchrow(
        """
        SELECT id, tenant_id, bundle_sha256, bundle_byte_size,
               target_count, customer_policy_ids,
               excluded_target_count, excluded_targets_log,
               built_at, signing_key_id, manifest
          FROM policy_bundles
         WHERE tenant_id = $1
         ORDER BY built_at DESC
         LIMIT 1
        """,
        tenant_user["tenant_id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="no bundle built yet")
    return BundleManifest(
        bundle_id=row["id"],
        tenant_id=row["tenant_id"],
        bundle_sha256=row["bundle_sha256"],
        bundle_byte_size=row["bundle_byte_size"],
        target_count=row["target_count"],
        customer_policy_ids=row["customer_policy_ids"],
        excluded_target_count=row["excluded_target_count"],
        excluded_targets_log=_ensure_json(row["excluded_targets_log"]),
        built_at=row["built_at"],
        signing_key_id=row["signing_key_id"],
        manifest=_ensure_json(row["manifest"]),
    )


@user_router.get("/{bundle_id}/manifest", response_model=BundleManifest)
async def get_bundle_manifest_by_id(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    bundle_id: UUID = Path(...),
) -> BundleManifest:
    """Full manifest for an arbitrary historical bundle.

    The /current/manifest endpoint only returns the most recent
    bundle; this endpoint lets the history table link each row to
    its full manifest detail. Tenant-scoped: a bundle ID owned by
    another tenant 404s identically to a non-existent ID, so we
    don't leak existence across tenants.
    """
    row = await pool.fetchrow(
        """
        SELECT id, tenant_id, bundle_sha256, bundle_byte_size,
               target_count, customer_policy_ids,
               excluded_target_count, excluded_targets_log,
               built_at, signing_key_id, manifest
          FROM policy_bundles
         WHERE id = $1 AND tenant_id = $2
        """,
        bundle_id,
        tenant_user["tenant_id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="bundle not found")
    return BundleManifest(
        bundle_id=row["id"],
        tenant_id=row["tenant_id"],
        bundle_sha256=row["bundle_sha256"],
        bundle_byte_size=row["bundle_byte_size"],
        target_count=row["target_count"],
        customer_policy_ids=row["customer_policy_ids"],
        excluded_target_count=row["excluded_target_count"],
        excluded_targets_log=_ensure_json(row["excluded_targets_log"]),
        built_at=row["built_at"],
        signing_key_id=row["signing_key_id"],
        manifest=_ensure_json(row["manifest"]),
    )


@user_router.get("", response_model=list[BundleHistoryEntry])
async def list_bundle_history(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user_mfa)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    limit: int = Query(50, ge=1, le=200),
    before_built_at: datetime | None = Query(
        None,
        description="Cursor — pass with before_id (both or neither). "
        "Returns entries strictly before this (built_at, id) pair.",
    ),
    before_id: UUID | None = Query(
        None,
        description="Tiebreaker for before_built_at. The bundle_id of "
        "the oldest entry from the prior page.",
    ),
) -> list[dict[str, Any]]:
    """Reverse-chronological history of bundles for the tenant.

    Lean payload — `bundle_bytes`, `signed_envelope_bytes`, and the
    full `manifest` jsonb are deliberately not returned here. A list
    page of dozens of entries would otherwise be tens of megabytes
    for no UI benefit. Per-bundle manifest detail lives on
    /me/bundles/{bundle_id}/manifest.

    Pagination is cursor-based on the compound `(built_at, id)` key
    to be collision-safe. Postgres timestamptz is microsecond-
    precision and bundle builds are rare, but two builds CAN land in
    the same microsecond; without the id tiebreaker the duplicate
    would appear on two pages. Result order is `built_at DESC,
    id DESC` so the cursor is deterministic.
    """
    if (before_built_at is None) != (before_id is None):
        # Both or neither — the cursor is a pair, not two independent
        # filters. Mixing them silently would let pagination drop or
        # repeat rows depending on which one was omitted.
        raise HTTPException(
            status_code=400,
            detail="before_built_at and before_id must be passed together",
        )

    if before_built_at is None:
        rows = await pool.fetch(
            """
            SELECT pb.id AS bundle_id, pb.bundle_sha256,
                   pb.bundle_byte_size, pb.target_count,
                   pb.excluded_target_count, pb.built_at,
                   pb.signing_key_id, tu.email AS built_by_email
              FROM policy_bundles pb
              LEFT JOIN tenant_users tu ON tu.id = pb.built_by_user_id
             WHERE pb.tenant_id = $1
             ORDER BY pb.built_at DESC, pb.id DESC
             LIMIT $2
            """,
            tenant_user["tenant_id"],
            limit,
        )
    else:
        rows = await pool.fetch(
            """
            SELECT pb.id AS bundle_id, pb.bundle_sha256,
                   pb.bundle_byte_size, pb.target_count,
                   pb.excluded_target_count, pb.built_at,
                   pb.signing_key_id, tu.email AS built_by_email
              FROM policy_bundles pb
              LEFT JOIN tenant_users tu ON tu.id = pb.built_by_user_id
             WHERE pb.tenant_id = $1
               AND (pb.built_at, pb.id) < ($2, $3)
             ORDER BY pb.built_at DESC, pb.id DESC
             LIMIT $4
            """,
            tenant_user["tenant_id"],
            before_built_at,
            before_id,
            limit,
        )
    return [dict(r) for r in rows]


# ── Public signing-key advertisement ──────────────────────────────────


public_router = APIRouter(prefix="/portal/v1/bundles", tags=["public:bundles"])


@public_router.get("/signing-key", response_model=SigningKeyInfo)
async def get_signing_key() -> SigningKeyInfo:
    """Unauthenticated endpoint for bridge onboarding.

    Returns the portal's current public key + key_id. Operators embed
    this in the bridge config at install time; bridge verifies the
    signed envelope on every pull. Public-key-only — no secret material
    served here ever.
    """
    s = get_settings()
    try:
        key_b64 = public_key_b64()
    except SigningKeyMissing as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return SigningKeyInfo(
        public_key_b64=key_b64,
        signing_key_id=s.bundle_signing_key_id,
    )
