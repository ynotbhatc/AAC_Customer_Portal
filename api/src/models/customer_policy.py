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
