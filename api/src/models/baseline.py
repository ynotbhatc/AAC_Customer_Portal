"""Pydantic models for baseline snapshots (Piece 50)."""
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, Field, conint


# Use a plain conint to keep stat values non-negative — the bridge
# could in principle send -1; we'd rather 422 than store nonsense.
NonNeg = Annotated[int, Field(ge=0)]


class BaselineFrameworkStats(BaseModel):
    """Per-framework slice of the aggregate. The keys are framework
    buckets (e.g. 'iso27001', 'pci_dss') — same name space as
    customer_policies.framework_bucket."""
    passing: NonNeg
    failing: NonNeg


class BaselineSummary(BaseModel):
    """The aggregate evaluation stats the bridge POSTs. Schema is the
    bridge's contract; the portal stores it opaque after Pydantic
    validation."""
    host_count: NonNeg
    total_evaluations: NonNeg
    passing: NonNeg
    failing: NonNeg
    errors: NonNeg = 0
    by_framework: dict[str, BaselineFrameworkStats] = Field(
        default_factory=dict,
        description=(
            "Per-framework breakdown. Optional — bridge can omit if it "
            "only has a global view."
        ),
    )


class BaselineIngestRequest(BaseModel):
    """Body the bridge POSTs to /tenants/{id}/baselines.

    `source` is set server-side to 'bridge_push' for this endpoint;
    a separate operator-side route can post with `source='manual'`.
    """
    bundle_sha256: str = Field(..., min_length=64, max_length=64)
    summary: BaselineSummary
    label: str | None = Field(default=None, max_length=200)


class BaselineSnapshotSummary(BaseModel):
    """List-view row. Omits the full `summary` jsonb to keep the
    payload light for the history table. The detail endpoint
    returns the full thing."""
    id: UUID
    tenant_id: UUID
    bundle_sha256: str
    captured_at: datetime
    captured_by_email: str | None = None
    label: str | None = None
    source: Literal["bridge_push", "manual", "scheduled"]
    host_count: int
    passing: int
    failing: int


class BaselineSnapshotDetail(BaselineSnapshotSummary):
    """Detail view — includes the full BaselineSummary, with its
    by_framework breakdown."""
    summary: BaselineSummary
