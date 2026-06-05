// Mirrors api/src/models/policy_audit.AuditLogEntry.
//
// `id` is bigserial server-side. JSON numbers are safe through
// ~2^53 — at append rates the portal currently produces, that's
// decades of headroom — so we stay with `number`. If we ever
// approach the limit, switch to `string` and adjust the cursor type.

export interface AuditLogEntry {
  id: number;
  action: string;
  details: Record<string, unknown>;
  at: string;
  tenant_user_id: string | null;
  // null when the actor's tenant_users row was deleted (FK is SET NULL).
  // UI renders that as "(user removed)" rather than blank.
  actor_email: string | null;
}
