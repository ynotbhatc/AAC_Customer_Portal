/**
 * Audit-log badge taxonomy tests.
 *
 * `AUDIT_ACTIONS` (in `types/auditActions.ts`) is the canonical
 * client-side list and mirrors `api/src/core/audit_actions.py`. This
 * test guarantees every canonical action gets a semantic (non-slate)
 * badge, so a backend addition without a frontend update can't
 * silently fall through to "unknown action" styling.
 */
import { describe, it, expect } from "vitest";

import { ALL_AUDIT_ACTIONS } from "../types/auditActions";
import { AUDIT_BADGE_FALLBACK, badgeClass } from "./auditBadge";


describe("badgeClass", () => {
  it("returns a styled (non-slate) class for every canonical action", () => {
    const missing: string[] = [];
    for (const action of ALL_AUDIT_ACTIONS) {
      if (badgeClass(action) === AUDIT_BADGE_FALLBACK) {
        missing.push(action);
      }
    }
    expect(missing).toEqual([]);
  });

  it("falls through to slate for unknown actions", () => {
    expect(badgeClass("not_a_real_action")).toBe(AUDIT_BADGE_FALLBACK);
  });
});
