"""Pydantic models for the policy_audit_log read endpoint.

The append-only `policy_audit_log` table is written from many places in
this codebase (publish, target review, bundle build, ...). This module
defines the *read* shape — what the customer portal renders when a
compliance team wants to know "who did what, when, to this policy."

Bundle-built events (customer_policy_id IS NULL) are not exposed here;
they're surfaced on the bundles page instead. The per-policy endpoint
filters to entries for one specific customer_policies row.
"""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AuditLogEntry(BaseModel):
    """One row from policy_audit_log, joined with the actor's email."""

    id: int
    action: str
    details: dict[str, Any] = Field(default_factory=dict)
    at: datetime
    # tenant_user_id can be NULL if the actor's row was deleted; in
    # that case actor_email is None too. The UI renders that as "(user
    # removed)" rather than a blank cell.
    tenant_user_id: str | None = None
    actor_email: str | None = None
