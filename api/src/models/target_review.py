"""Pydantic models for customer-side target review workflow."""
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class TargetSummary(BaseModel):
    """List view of a customer_policy_targets row.
    Does NOT include the Rego text — fetched per-target via the
    detail endpoint to keep the list payload small."""
    id: UUID
    customer_policy_id: UUID
    target_system: str
    target_subtype: str | None = None
    generation_method: str
    confidence_score: float | None = None
    review_status: Literal["pending", "approved", "rejected"]
    rego_content_sha256: str
    published_in_bundle_sha: str | None = None
    created_at: datetime


class TargetDetail(TargetSummary):
    """Detail view — includes the Rego text and the upstream storage key."""
    rego_storage_key: str
    rego_text: str


class TargetEditRequest(BaseModel):
    """Body for PATCH /me/policies/{policy_id}/targets/{target_id}."""
    rego_text: str = Field(..., min_length=1, max_length=200_000)


class TargetReviewAction(BaseModel):
    """Body for /approve and /reject endpoints. Reason is required on
    reject (forces the reviewer to record WHY the Rego was bad) and
    optional on approve."""
    reason: str | None = Field(default=None, max_length=2000)
