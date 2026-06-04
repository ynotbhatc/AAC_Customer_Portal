"""Pydantic models for customer_policies + upload endpoints.

The MVP exposes a subset of the schema columns — Tier 1 governance
fields (control_owner_user_id, review_cadence_days, etc.) are stored
but not surfaced in the API yet, per design §2.1 (measurable-first).
"""
from datetime import date, datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


PolicySource = Literal["prose_upload", "forked_overlay", "customer_original"]
PolicyStatus = Literal["draft", "in_review", "published", "archived"]


class UploadAccepted(BaseModel):
    """Returned by POST /portal/v1/me/policies/upload — the user gets
    back the draft customer_policy plus the upload record id so the
    UI can show "1.2 MB processed → 3,847 chars extracted"."""
    customer_policy_id: UUID
    upload_id: UUID
    original_filename: str
    sniffed_mime: str
    byte_size: int
    extracted_text_chars: int


class CustomerPolicySummary(BaseModel):
    """List view — does NOT include the full IR or extracted text;
    that's fetched per-policy on demand to keep the list payload small."""
    id: UUID
    tenant_id: UUID
    name: str
    framework_bucket: str
    policy_source: PolicySource
    version_semver: str
    effective_date: date | None = None
    status: PolicyStatus
    created_at: datetime
    updated_at: datetime


class CustomerPolicyDetail(CustomerPolicySummary):
    """Full row — fetched by GET /portal/v1/me/policies/{id}."""
    source_file_storage_key: str | None = None
    source_file_mime: str | None = None
    parent_standard_ref: str | None = None
    parent_standard_version: str | None = None
    ir_json: dict | None = None


class GeneratedTargetSummary(BaseModel):
    """One per-target Rego artifact summary returned by the generator."""
    customer_policy_target_id: UUID
    target_system: str
    target_subtype: str | None = None
    generation_method: str       # template_mapped | llm_fallback
    confidence_score: float | None = None
    review_status: str           # pending | rejected
    opa_check_ok: bool
    rego_storage_key: str
    rego_content_sha256: str
    llm_attempts: int
    model: str | None = None
    opa_check_stderr: str | None = None  # populated only when review_status='rejected'


class RegoGenerationResponse(BaseModel):
    """Returned by POST /portal/v1/me/policies/{id}/generate-rego."""
    customer_policy_id: UUID
    targets_generated: int
    targets_pending_review: int
    targets_rejected: int
    targets: list[GeneratedTargetSummary]


class IRExtractionResponse(BaseModel):
    """Returned by POST /portal/v1/me/policies/{id}/extract-ir.

    Echoes the IR document the endpoint just wrote into the row, plus
    a count of how many controls landed inside the closed enum (vs
    those marked null) — useful for the review UI's "8/12 controls
    matched the library, 4 are free-form" badge.
    """
    customer_policy_id: UUID
    schema_version: str
    control_count: int
    controls_matched_library: int
    controls_freeform: int
    ir_json: dict
