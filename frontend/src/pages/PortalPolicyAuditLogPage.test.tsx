/**
 * Audit-log badge tests — pin the action-string taxonomy.
 *
 * The list of canonical action strings lives in
 * `frontend/src/types/auditActions.ts` and mirrors
 * `api/src/core/audit_actions.py::AuditAction`. This test asserts
 * that every canonical action gets a semantic (non-slate) badge,
 * so a backend addition without a frontend update can't silently
 * fall through to the "unknown action" styling.
 */
import { describe, it, expect } from "vitest";

import { ALL_AUDIT_ACTIONS } from "../types/auditActions";
import { badgeClass } from "./PortalPolicyAuditLogPage";


const FALLBACK = "bg-slate-100 text-slate-700";


describe("badgeClass", () => {
  it("returns a styled (non-slate) class for every canonical action", () => {
    const missing: string[] = [];
    for (const action of ALL_AUDIT_ACTIONS) {
      if (badgeClass(action) === FALLBACK) {
        missing.push(action);
      }
    }
    expect(missing).toEqual([]);
  });

  it("falls through to slate for unknown actions", () => {
    expect(badgeClass("not_a_real_action")).toBe(FALLBACK);
  });
});
