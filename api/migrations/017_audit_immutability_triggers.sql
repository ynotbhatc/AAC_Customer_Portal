-- Migration 017 — Append-only enforcement on audit + baseline tables
--
-- `policy_audit_log` and `baseline_snapshots` are conceptually
-- append-only: rows in them are the source of truth an external
-- auditor reads to answer "what did this tenant do, when?". The schema
-- comments and application code already treat them that way — but
-- without a DB-level guard, a privileged account with a typo, a
-- compromised credential, or a malicious insider could silently rewrite
-- history.
--
-- This migration adds BEFORE UPDATE and BEFORE DELETE triggers that
-- RAISE EXCEPTION on every attempt. There is ONE allowed exception
-- to UPDATE: FK cascade SET NULL on the nullable actor / policy
-- columns. That pattern fires when a tenant_user (or customer_policy)
-- is hard-deleted — the FK definitions for those columns are
-- ON DELETE SET NULL, and we want the audit row to survive with its
-- foreign key nulled out rather than disappear. So an UPDATE that
-- only sets `tenant_user_id` or `customer_policy_id` from non-NULL
-- to NULL is permitted; every other column-change combination is
-- rejected.
--
-- DELETE is unconditionally rejected. That means a hard DELETE on
-- `tenants` (FK cascade → DELETE on policy_audit_log) is now also
-- rejected. In practice tenants are soft-deleted (UPDATE tenants SET
-- status = 'deleted'), so this is the correct contract. A legitimate
-- "purge tenant" procedure must DROP the trigger, run the purge with a
-- system_audit_log entry naming the operator, then re-CREATE the
-- trigger.
--
-- Out of scope: TTL / retention policy + per-row legal-hold flag.
-- Those are a separate SOC 2 prep PR.

BEGIN;


-- ── policy_audit_log ──────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION enforce_policy_audit_log_append_only()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'policy_audit_log: DELETE rejected — table is append-only (immutability trigger)'
            USING ERRCODE = 'check_violation';
    END IF;

    -- TG_OP = 'UPDATE'. Allowed change: tenant_user_id and/or
    -- customer_policy_id go from non-NULL to NULL (FK SET NULL
    -- cascade). Every other column change is forbidden.
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
            'policy_audit_log: UPDATE rejected — table is append-only (only FK SET NULL cascade permitted)'
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_policy_audit_log_no_update ON policy_audit_log;
CREATE TRIGGER trg_policy_audit_log_no_update
    BEFORE UPDATE ON policy_audit_log
    FOR EACH ROW EXECUTE FUNCTION enforce_policy_audit_log_append_only();

DROP TRIGGER IF EXISTS trg_policy_audit_log_no_delete ON policy_audit_log;
CREATE TRIGGER trg_policy_audit_log_no_delete
    BEFORE DELETE ON policy_audit_log
    FOR EACH ROW EXECUTE FUNCTION enforce_policy_audit_log_append_only();


-- ── baseline_snapshots ────────────────────────────────────────────────
-- Same shape; the only FK that's ON DELETE SET NULL is
-- captured_by_user_id. tenant_id is ON DELETE CASCADE, which fires
-- DELETE on this table and lands in the unconditional block.
CREATE OR REPLACE FUNCTION enforce_baseline_snapshots_append_only()
RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'baseline_snapshots: DELETE rejected — table is append-only (immutability trigger)'
            USING ERRCODE = 'check_violation';
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
            'baseline_snapshots: UPDATE rejected — table is append-only (only FK SET NULL cascade permitted)'
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_baseline_snapshots_no_update ON baseline_snapshots;
CREATE TRIGGER trg_baseline_snapshots_no_update
    BEFORE UPDATE ON baseline_snapshots
    FOR EACH ROW EXECUTE FUNCTION enforce_baseline_snapshots_append_only();

DROP TRIGGER IF EXISTS trg_baseline_snapshots_no_delete ON baseline_snapshots;
CREATE TRIGGER trg_baseline_snapshots_no_delete
    BEFORE DELETE ON baseline_snapshots
    FOR EACH ROW EXECUTE FUNCTION enforce_baseline_snapshots_append_only();


COMMIT;
