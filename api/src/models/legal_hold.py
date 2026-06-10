"""Pydantic models for the legal-hold admin API.

The DB-level mechanism (`legal_hold_reason text NULL` + immutability
triggers) was introduced in migration 018. This API wraps the
runbook SQL in a typed surface so operators don't shell into psql
for routine apply/release.

Supports two tables: `policy_audit_log` (bigserial id) and
`baseline_snapshots` (uuid id). The `resource_id` field is `str` so
callers can pass either form; the router validates against the
declared `resource_type` before issuing SQL.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


LegalHoldTable = Literal["policy_audit_log", "baseline_snapshots"]


class LegalHoldApply(BaseModel):
    """Request body for `POST /admin/v1/legal-holds`.

    `reason` and `approval_ticket` are both required and both land
    in the persisted record:
      - `reason` becomes the row's `legal_hold_reason` text (auditor-
        visible at the DB layer).
      - `approval_ticket` is captured in the `system_audit_log.details`
        JSON for the apply event, so an auditor can trace back to the
        legal authorisation document.
    """
    resource_type: LegalHoldTable
    resource_id: str = Field(..., min_length=1)
    reason: str = Field(
        ...,
        min_length=5,
        description="Auditor-visible justification stored on the row. "
        "Keep concise and specific (e.g. 'SEC-2026-014 preservation order').",
    )
    approval_ticket: str = Field(
        ...,
        min_length=1,
        description="External ticket / docket reference authorising the hold. "
        "Captured in the audit log; not stored on the held row itself.",
    )


class LegalHoldRelease(BaseModel):
    """Request body for `DELETE /admin/v1/legal-holds/{type}/{id}`.

    The release ticket is required for the same reason the apply
    ticket is required: someone is making a legal-impact decision,
    and the audit log needs to anchor that decision to an external
    authorisation document.
    """
    release_ticket: str = Field(
        ...,
        min_length=1,
        description="External ticket / docket reference authorising the release.",
    )


class LegalHoldEntry(BaseModel):
    """Returned by `GET /admin/v1/legal-holds` — one row per held entry."""
    resource_type: LegalHoldTable
    resource_id: str
    reason: str
    tenant_id: str
