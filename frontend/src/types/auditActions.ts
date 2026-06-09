/**
 * Canonical audit-action taxonomy.
 *
 * Mirrors `api/src/core/audit_actions.py::AuditAction`. The portal
 * stores these strings in `policy_audit_log.action`; the UI renders
 * them as badges. Backend and frontend share this list so the badge
 * styling never falls out of sync — see backend test
 * `test_audit_actions.py::test_enum_covers_router_inserts` and
 * frontend test `auditActions.test.ts`.
 *
 * Strings are stable on-disk values — never rename one, only deprecate.
 */
export const AUDIT_ACTIONS = {
  UPLOADED: "uploaded",
  IR_EXTRACTED: "ir_extracted",
  REGO_GENERATED: "rego_generated",
  PUBLISHED: "published",
  FORKED: "forked",
  TARGET_EDITED: "target_edited",
  TARGET_APPROVED: "target_approved",
  TARGET_REJECTED: "target_rejected",
  REPUBLISHED_FROM: "republished_from",
  BUNDLE_BUILT: "bundle_built",
} as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[keyof typeof AUDIT_ACTIONS];

export const ALL_AUDIT_ACTIONS: readonly AuditAction[] = Object.values(AUDIT_ACTIONS);
