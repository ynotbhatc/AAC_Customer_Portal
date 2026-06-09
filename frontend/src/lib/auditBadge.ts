/**
 * Audit-action badge styling — extracted from the page so it can be
 * unit-tested without rendering the React tree, and so the page file
 * stays compliant with `react-refresh/only-export-components`.
 *
 * Action strings come from `AUDIT_ACTIONS` (canonical, shared with the
 * backend). Unknown actions fall through to slate — new INSERT shapes
 * can land without breaking the UI.
 */
import { AUDIT_ACTIONS } from "../types/auditActions";

export const AUDIT_BADGE_FALLBACK = "bg-slate-100 text-slate-700";

export function badgeClass(action: string): string {
  if (
    action === AUDIT_ACTIONS.PUBLISHED ||
    action === AUDIT_ACTIONS.TARGET_APPROVED
  ) {
    return "bg-emerald-100 text-emerald-800";
  }
  if (action === AUDIT_ACTIONS.TARGET_REJECTED) {
    return "bg-red-100 text-red-800";
  }
  if (action === AUDIT_ACTIONS.TARGET_EDITED) {
    return "bg-amber-100 text-amber-800";
  }
  if (action === AUDIT_ACTIONS.BUNDLE_BUILT) {
    return "bg-blue-100 text-blue-800";
  }
  if (
    action === AUDIT_ACTIONS.UPLOADED ||
    action === AUDIT_ACTIONS.IR_EXTRACTED ||
    action === AUDIT_ACTIONS.REGO_GENERATED ||
    action === AUDIT_ACTIONS.FORKED ||
    action === AUDIT_ACTIONS.REPUBLISHED_FROM
  ) {
    return "bg-sky-100 text-sky-800";
  }
  return AUDIT_BADGE_FALLBACK;
}
