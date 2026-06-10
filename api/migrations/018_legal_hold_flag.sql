-- Migration 018 — Per-row legal hold on policy_audit_log + baseline_snapshots
--
-- Adds `legal_hold_reason text NULL` to both audit tables. When the
-- column is non-NULL, the row is on legal hold: a litigation hold, an
-- active SOC-2 audit window, a regulator's data preservation order,
-- etc. While on hold:
--
--   - DELETE (direct or FK cascade) is rejected
--   - UPDATE of any column EXCEPT legal_hold_reason itself is rejected
--   - The FK SET NULL cascade allowance from migration 017 is suspended
--     (so deleting a tenant_user with legal-held audit history fails;
--      the operator must clear the hold first, which itself audits)
--
-- The `_reason` text doubles as the "is on hold?" predicate AND the
-- audit field: an auditor asking "what's on legal hold and why?" gets
-- one query: SELECT id, legal_hold_reason FROM ... WHERE legal_hold_reason IS NOT NULL.
--
-- Operator procedure for setting / clearing the flag lives in
-- docs/runbooks/legal_hold.md. Like the tenant-purge runbook, the
-- set + clear operations are performed via direct SQL with a manual
-- system_audit_log entry recording the operator + ticket reference.
-- An API endpoint is a follow-up PR.
--
-- Trigger logic update is the meaty part. The previous (migration
-- 017) triggers ran:
--
--   IF (any column except FK-SET-NULL columns changed) THEN REJECT.
--
-- The new triggers run:
--
--   IF DELETE: REJECT unconditionally.
--   IF UPDATE:
--     IF OLD.legal_hold_reason IS NOT NULL:
--       The only allowed change is legal_hold_reason itself (any
--       value — including NULL to clear the hold). Every other
--       column must match OLD exactly.
--     ELSE:
--       The migration-017 rules apply, PLUS legal_hold_reason MAY
--       transition from NULL to non-NULL (setting the hold).

BEGIN;


-- ── policy_audit_log ──────────────────────────────────────────────────
ALTER TABLE policy_audit_log
    ADD COLUMN IF NOT EXISTS legal_hold_reason text NULL;

CREATE INDEX IF NOT EXISTS idx_policy_audit_log_legal_hold
    ON policy_audit_log (id)
    WHERE legal_hold_reason IS NOT NULL;


CREATE OR REPLACE FUNCTION enforce_policy_audit_log_append_only()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'policy_audit_log: DELETE rejected — table is append-only (immutability trigger)'
            USING ERRCODE = 'check_violation';
    END IF;

    -- TG_OP = 'UPDATE'.
    IF OLD.legal_hold_reason IS NOT NULL THEN
        -- Row is on legal hold. The only allowed change is to
        -- legal_hold_reason itself (set to a new reason, or NULL
        -- to clear the hold). Every other column must match.
        IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.tenant_user_id IS DISTINCT FROM OLD.tenant_user_id
           OR NEW.customer_policy_id IS DISTINCT FROM OLD.customer_policy_id
           OR NEW.action IS DISTINCT FROM OLD.action
           OR NEW.details IS DISTINCT FROM OLD.details
           OR NEW.at IS DISTINCT FROM OLD.at
        THEN
            RAISE EXCEPTION
                'policy_audit_log: UPDATE rejected — row is on legal hold (clear legal_hold_reason first)'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    -- Row is NOT on legal hold. Apply the migration-017 rules:
    -- only FK SET NULL cascade is permitted, PLUS legal_hold_reason
    -- MAY transition from NULL to non-NULL (setting the hold).
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.action IS DISTINCT FROM OLD.action
       OR NEW.details IS DISTINCT FROM OLD.details
       OR NEW.at IS DISTINCT FROM OLD.at
       OR (NEW.tenant_user_id IS NOT NULL
           AND NEW.tenant_user_id IS DISTINCT FROM OLD.tenant_user_id)
       OR (NEW.customer_policy_id IS NOT NULL
           AND NEW.customer_policy_id IS DISTINCT FROM OLD.customer_policy_id)
    THEN
        RAISE EXCEPTION
            'policy_audit_log: UPDATE rejected — table is append-only (only FK SET NULL cascade or legal-hold set permitted)'
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- ── baseline_snapshots ────────────────────────────────────────────────
ALTER TABLE baseline_snapshots
    ADD COLUMN IF NOT EXISTS legal_hold_reason text NULL;

CREATE INDEX IF NOT EXISTS idx_baseline_snapshots_legal_hold
    ON baseline_snapshots (id)
    WHERE legal_hold_reason IS NOT NULL;


CREATE OR REPLACE FUNCTION enforce_baseline_snapshots_append_only()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'baseline_snapshots: DELETE rejected — table is append-only (immutability trigger)'
            USING ERRCODE = 'check_violation';
    END IF;

    IF OLD.legal_hold_reason IS NOT NULL THEN
        IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
           OR NEW.captured_by_user_id IS DISTINCT FROM OLD.captured_by_user_id
           OR NEW.bundle_sha256 IS DISTINCT FROM OLD.bundle_sha256
           OR NEW.captured_at IS DISTINCT FROM OLD.captured_at
           OR NEW.label IS DISTINCT FROM OLD.label
           OR NEW.summary IS DISTINCT FROM OLD.summary
           OR NEW.source IS DISTINCT FROM OLD.source
        THEN
            RAISE EXCEPTION
                'baseline_snapshots: UPDATE rejected — row is on legal hold (clear legal_hold_reason first)'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.bundle_sha256 IS DISTINCT FROM OLD.bundle_sha256
       OR NEW.captured_at IS DISTINCT FROM OLD.captured_at
       OR NEW.label IS DISTINCT FROM OLD.label
       OR NEW.summary IS DISTINCT FROM OLD.summary
       OR NEW.source IS DISTINCT FROM OLD.source
       OR (NEW.captured_by_user_id IS NOT NULL
           AND NEW.captured_by_user_id IS DISTINCT FROM OLD.captured_by_user_id)
    THEN
        RAISE EXCEPTION
            'baseline_snapshots: UPDATE rejected — table is append-only (only FK SET NULL cascade or legal-hold set permitted)'
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;


COMMIT;
