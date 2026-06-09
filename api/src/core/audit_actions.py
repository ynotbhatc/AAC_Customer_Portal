"""Canonical audit-action taxonomy for `policy_audit_log`.

Single source of truth for the action strings that routers write into
`policy_audit_log.action` and that the portal UI renders as badges.
Backend code MUST use these constants (not raw strings) so the
backend ↔ frontend contract stays in sync; the matching frontend
constants live at `frontend/src/types/auditActions.ts`.

Strings are stable on-disk values — they are stored in the audit log
and read back forever. Never rename one; add a new member and
deprecate the old, never both at once.
"""
from __future__ import annotations

from enum import Enum


class AuditAction(str, Enum):
    """Canonical action strings written into `policy_audit_log.action`."""

    UPLOADED = "uploaded"
    IR_EXTRACTED = "ir_extracted"
    REGO_GENERATED = "rego_generated"
    PUBLISHED = "published"
    FORKED = "forked"
    TARGET_EDITED = "target_edited"
    TARGET_APPROVED = "target_approved"
    TARGET_REJECTED = "target_rejected"
    REPUBLISHED_FROM = "republished_from"
    BUNDLE_BUILT = "bundle_built"


# Public set, useful for membership checks in tests and validation.
ALL_AUDIT_ACTIONS: frozenset[str] = frozenset(a.value for a in AuditAction)
