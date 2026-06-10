# Runbook — Hard-Delete a Tenant ("Tenant Purge")

**Audience:** Operator with `PORTAL_ADMIN_TOKEN` + database superuser.
**Trigger:** Tenant has requested deletion of all data (e.g. GDPR
right-to-erasure), or an offboarding contract requires the portal to
prove the customer's data is no longer retained. Routine offboarding
should use soft-delete (`UPDATE tenants SET status='deleted'`) — this
runbook is for the rare case where the row itself must go.

**Why this needs a runbook:** as of migration 017
(`017_audit_immutability_triggers.sql`), the append-only triggers on
`policy_audit_log` and `baseline_snapshots` reject every UPDATE / DELETE
that isn't a narrowly-scoped FK SET NULL cascade. Hard-deleting a
`tenant` row would cascade-DELETE the corresponding `baseline_snapshots`
rows, and the trigger blocks that. So a hard tenant purge is not a
one-liner — it requires temporarily lifting the gate.

---

## Pre-conditions

Before starting:

1. **Legal / compliance approval is captured in writing.** The audit
   trail you are about to destroy is the source of evidence an external
   auditor uses. Make sure the approval to destroy it is itself
   recorded outside this system.

2. **The tenant has no live `tenant_user_sessions`.** Revoke all of
   them via the operator endpoint or directly:

   ```sql
   UPDATE tenant_user_sessions
      SET revoked_at = now(),
          revoked_reason = 'tenant_purge'
    WHERE tenant_user_id IN (
        SELECT id FROM tenant_users WHERE tenant_id = :TENANT_ID
    ) AND revoked_at IS NULL;
   ```

3. **Bridges are no longer pulling.** Revoke every `tenant_token` for
   the tenant. Verify there is no recent (last 5 minutes) `last_used_at`
   in `tenant_tokens` for the tenant — the bridge polls roughly that
   often.

4. **Backups are current.** `pg_dump` the entire portal DB or take a
   storage snapshot. The purge is irreversible; the backup is your
   undo button if you discover a mistake.

---

## Procedure

All steps run as the database superuser (not `aac_portal_app`),
because `DROP TRIGGER` is owner-only on tables the app role does not
own. Each step is intended to be auditable; do not abbreviate.

### 1. Open a single transaction

```sql
BEGIN;
```

Keeping the whole purge in one transaction means a partial failure
does not leave the DB in an inconsistent state: either every step
commits, or every step rolls back.

### 2. Drop the immutability triggers

```sql
DROP TRIGGER trg_policy_audit_log_no_update ON policy_audit_log;
DROP TRIGGER trg_policy_audit_log_no_delete ON policy_audit_log;
DROP TRIGGER trg_baseline_snapshots_no_update ON baseline_snapshots;
DROP TRIGGER trg_baseline_snapshots_no_delete ON baseline_snapshots;
```

The trigger functions are kept (a future CREATE TRIGGER references them
by name); only the bindings are dropped.

### 3. Record the operator intent in `system_audit_log`

Direct INSERT, because the request is not coming through the API:

```sql
INSERT INTO system_audit_log
    (tenant_id, method, path, status_code,
     resource_type, resource_id, details)
VALUES
    (:TENANT_ID, 'PURGE', '/runbooks/tenant_purge.md', 200,
     'tenant', :TENANT_ID,
     jsonb_build_object(
         'operator', :OPERATOR_EMAIL,
         'approval_ticket', :TICKET_OR_TASK_REF,
         'reason', :REASON_TEXT
     ));
```

The `method='PURGE'` is non-HTTP and is the audit signal that this
operation happened outside the normal API surface. Auditors querying
`system_audit_log` by `(method = 'PURGE', resource_type = 'tenant')`
will surface every purge ever performed against this database — even
the rows that the purge itself deleted, because `system_audit_log` is
not subject to migration 017's triggers.

### 4. Hard-delete the tenant

```sql
DELETE FROM tenants WHERE id = :TENANT_ID;
```

PostgreSQL fans out via the FK CASCADE chain:

- `tenant_users`, `tenant_user_sessions`, `tenant_user_password_resets`,
  `tenant_user_mfa_factors`
- `tenant_tokens`, `tenant_inventory_catalog`, `tenant_pull_runs`
- `customer_policies` → `customer_policy_targets`,
  `policy_uploads`, `policy_bundles`
- `policy_audit_log` (CASCADE)
- `baseline_snapshots` (CASCADE)
- `tenant_enrollments`, `tenant_vendor_subscriptions`,
  `tenant_filter_preferences`, `tenant_cve_matches`, `match_runs`
- `tenant_host_mappings`

Every dependent row goes with the parent. Triggers are dropped so the
cascade reaches every table.

### 5. Restore the immutability triggers

```sql
CREATE TRIGGER trg_policy_audit_log_no_update
    BEFORE UPDATE ON policy_audit_log
    FOR EACH ROW EXECUTE FUNCTION enforce_policy_audit_log_append_only();

CREATE TRIGGER trg_policy_audit_log_no_delete
    BEFORE DELETE ON policy_audit_log
    FOR EACH ROW EXECUTE FUNCTION enforce_policy_audit_log_append_only();

CREATE TRIGGER trg_baseline_snapshots_no_update
    BEFORE UPDATE ON baseline_snapshots
    FOR EACH ROW EXECUTE FUNCTION enforce_baseline_snapshots_append_only();

CREATE TRIGGER trg_baseline_snapshots_no_delete
    BEFORE DELETE ON baseline_snapshots
    FOR EACH ROW EXECUTE FUNCTION enforce_baseline_snapshots_append_only();
```

The bindings must be re-created before the transaction commits. If
you forget this step and `COMMIT`, the next operator inherits an
unprotected audit log until someone notices.

### 6. Verify the bindings are back, then commit

```sql
SELECT tgname FROM pg_trigger
 WHERE tgrelid IN ('policy_audit_log'::regclass, 'baseline_snapshots'::regclass)
   AND NOT tgisinternal
 ORDER BY tgname;
```

You must see four rows:

- `trg_baseline_snapshots_no_delete`
- `trg_baseline_snapshots_no_update`
- `trg_policy_audit_log_no_delete`
- `trg_policy_audit_log_no_update`

If you see fewer, restore from the backup taken in pre-conditions.

```sql
COMMIT;
```

### 7. Post-commit verification

```sql
-- Tenant gone:
SELECT count(*) FROM tenants WHERE id = :TENANT_ID;        -- expect 0

-- All children gone:
SELECT count(*) FROM tenant_users  WHERE tenant_id = :TENANT_ID;  -- 0
SELECT count(*) FROM policy_audit_log    WHERE tenant_id = :TENANT_ID; -- 0
SELECT count(*) FROM baseline_snapshots  WHERE tenant_id = :TENANT_ID; -- 0

-- Triggers are still active — try an UPDATE on an unrelated audit row:
UPDATE policy_audit_log SET action = action WHERE id = (
    SELECT id FROM policy_audit_log LIMIT 1
);
-- Expected: ERROR — policy_audit_log: UPDATE rejected
```

The trigger restoration is verified by the UPDATE actually failing. If
it succeeds, the restore step was skipped or wrong — restore from
backup and try again.

---

## What this runbook does NOT do

- **Bundle bytes are NOT removed from anywhere outside the DB.** If
  `policy_bundles.bundle_bytes` was mirrored to S3 or a CDN, that copy
  must be deleted separately.
- **`system_audit_log` is not purged.** The audit trail describing what
  the operator did persists. This is intentional — auditors must be
  able to see the purge happened.
- **No application-layer cache is invalidated.** The portal API is
  generally stateless, but if a process is running with a cached
  `tenant` object in memory, restart it after the purge.

---

## Recovery

If the purge fails partway and the transaction is rolled back, no DB
changes persist. If something worse happens (e.g., the connection drops
between `DELETE FROM tenants` and the trigger restore, and `COMMIT`
fires anyway because the client retried), restore the backup taken in
pre-conditions and start again.
