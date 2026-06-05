"""Pydantic models for publish + signed bundle delivery."""
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class PublishResponse(BaseModel):
    customer_policy_id: UUID
    status: str
    published_at: datetime
    version_semver: str


class BundleManifest(BaseModel):
    """Public manifest view returned by /bundles/current/manifest.
    Includes every field the bridge needs to log what it loaded;
    does NOT include the bundle bytes or the signing key material."""
    bundle_id: UUID
    tenant_id: UUID
    bundle_sha256: str
    bundle_byte_size: int
    target_count: int
    customer_policy_ids: list[UUID]
    excluded_target_count: int
    excluded_targets_log: list[dict[str, Any]]
    built_at: datetime
    signing_key_id: str
    manifest: dict[str, Any] = Field(
        ..., description="Full per-target metadata produced by the builder."
    )


class SigningKeyInfo(BaseModel):
    """Unauthenticated bridge-bootstrap response from /bundles/signing-key.
    Embedded once at tenant onboarding so the bridge can verify the
    signed envelope on every pull."""
    algorithm: str = "ed25519"
    public_key_b64: str
    signing_key_id: str


class BuildBundleResponse(BaseModel):
    """Returned by POST /portal/v1/me/bundles/build."""
    bundle_id: UUID
    bundle_sha256: str
    bundle_byte_size: int
    target_count: int
    excluded_target_count: int
    customer_policy_ids: list[UUID]
    built_at: datetime
    signing_key_id: str


class BundleHistoryEntry(BaseModel):
    """Lean row for the bundle history list endpoint.

    Deliberately omits the heavy fields — `bundle_bytes`,
    `signed_envelope_bytes`, and the full `manifest` jsonb — so a
    page of dozens of entries stays small. The full manifest is
    fetched per-bundle on demand if/when we add a detail surface.
    """
    bundle_id: UUID
    bundle_sha256: str
    bundle_byte_size: int
    target_count: int
    excluded_target_count: int
    built_at: datetime
    signing_key_id: str
    # NULL when the builder's tenant_users row was deleted (FK is SET NULL).
    built_by_email: str | None = None
