# Runbook — Apply or Release a Legal Hold

**Audience:** Operator with `PORTAL_ADMIN_TOKEN` (primary path) or database superuser access (break-glass).
**Trigger:** External legal / compliance event requires that specific audit rows be preserved past their normal lifecycle: litigation hold, regulator preservation order, SOC-2 audit window for a specific tenant, internal incident-response forensics window.

**Scope:** This runbook covers `policy_audit_log` and `baseline_snapshots`. Both tables grew a `legal_hold_reason text NULL` column in migration 018. When the column is non-NULL on a row, the immutability triggers escalate from "append-only" to "absolutely frozen except for the hold itself" — no UPDATE of any other column, no DELETE (direct or cascade), no FK SET NULL.

## Primary path: admin API

Use the typed admin endpoints. The API wraps the SQL flow below
and writes the same `system_audit_log` rows.

```bash
# Apply
curl -X POST "$PORTAL_URL/api/admin/v1/legal-holds" \
  -H "Authorization: Bearer $PORTAL_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_type": "policy_audit_log",
    "resource_id": "12345",
    "reason": "SEC-2026-014 preservation order",
    "approval_ticket": "INTERNAL-LEGAL-9182"
  }'

# Release
curl -X DELETE "$PORTAL_URL/api/admin/v1/legal-holds/policy_audit_log/12345" \
  -H "Authorization: Bearer $PORTAL_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"release_ticket": "INTERNAL-LEGAL-9183"}'

# Enumerate
curl "$PORTAL_URL/api/admin/v1/legal-holds" \
  -H "Authorization: Bearer $PORTAL_ADMIN_TOKEN"
```

The API rejects:

- Apply against a row that's already on hold (`409`) — to change the reason, release and re-apply.
- Apply with a `reason` shorter than 5 characters (`422`) — placeholder reasons aren't audit-defensible.
- Wrong ID type per table (`400`) — `policy_audit_log.id` is bigint, `baseline_snapshots.id` is uuid.
- Release of a row that's not on hold (`409`) — surfaces a wrong-row-id error instead of silently no-op'ing.

The direct-SQL path below remains documented for **break-glass** use when the API is unavailable (network partition, portal service down). The DB-level semantics are identical — the API is a typed wrapper, not a separate enforcement layer.

---

## Break-glass: direct SQL

The remaining sections describe the SQL flow the API wraps. Use them only when the portal API is unreachable.

## Apply a hold

### 1. Identify the rows

Decide whether the scope is:

- **A single audit row** (e.g. preserving one specific operator action because it's evidence in an investigation):

  ```sql
  SELECT id, tenant_id, action, at
    FROM policy_audit_log
   WHERE id = :AUDIT_ROW_ID;
  ```

- **All audit history for one tenant** (the most common case):

  ```sql
  SELECT id, action, at
    FROM policy_audit_log
   WHERE tenant_id = :TENANT_ID
   ORDER BY at;
  ```

- **One or more baseline snapshots** (e.g. preserving the compliance posture as of a specific date):

  ```sql
  SELECT id, captured_at, label
    FROM baseline_snapshots
   WHERE tenant_id = :TENANT_ID AND captured_at >= :CUTOFF;
  ```

Capture the row IDs you intend to hold — the audit trail entry references them.

### 2. Wrap in a transaction

```sql
BEGIN;
```

Every hold-apply runs in a single transaction so the system_audit_log entry and the table UPDATE land together. Either both commit, or neither.

### 3. Record the operator intent

```sql
INSERT INTO system_audit_log
    (tenant_id, method, path, status_code,
     resource_type, resource_id, details)
VALUES
    (:TENANT_ID, 'LEGAL_HOLD_APPLY', '/runbooks/legal_hold.md', 200,
     'policy_audit_log', :ROW_ID,
     jsonb_build_object(
         'operator', :OPERATOR_EMAIL,
         'approval_ticket', :TICKET_OR_DOCKET_REF,
         'reason', :REASON_TEXT,
         'row_count', :ROW_COUNT
     ));
```

`method='LEGAL_HOLD_APPLY'` is non-HTTP and is the audit signal that the row sits outside the normal API path. Use one INSERT per row held — that way an auditor querying `system_audit_log` gets a 1:1 correspondence between system_audit entries and held rows.

### 4. Set the flag

```sql
-- Single row:
UPDATE policy_audit_log
   SET legal_hold_reason = :REASON_TEXT
 WHERE id = :ROW_ID;

-- Or for a tenant scope:
UPDATE policy_audit_log
   SET legal_hold_reason = :REASON_TEXT
 WHERE tenant_id = :TENANT_ID
   AND legal_hold_reason IS NULL;  -- don't clobber any pre-existing hold
```

The `WHERE legal_hold_reason IS NULL` clause is important when scoping to a tenant or date range: if any row already has a hold (with a possibly different reason), we don't want this apply-action to clobber it. A pre-existing hold means a different legal matter is already preserving that row — keep its reason intact.

### 5. Verify and commit

```sql
SELECT count(*) FROM policy_audit_log
 WHERE legal_hold_reason = :REASON_TEXT;
-- Expected: row_count from step 3.

COMMIT;
```

If the count is wrong, `ROLLBACK` and investigate before retrying.

### 6. File the approval / preservation order

The approval ticket referenced in step 3 should itself be permanently retrievable (legal team's case-management system, not just the operator's email). The auditable trail in `system_audit_log` references the ticket; the ticket references the preservation order or court filing.

---

## Release a hold

### 1. Confirm the legal matter is closed

The operator releasing a hold must have written authorisation that the legal preservation requirement no longer applies. The ticket in `system_audit_log.details.approval_ticket` from the apply step is the anchor; the release ticket should reference the same.

### 2. Single transaction, audit entry, clear the flag

```sql
BEGIN;

INSERT INTO system_audit_log
    (tenant_id, method, path, status_code,
     resource_type, resource_id, details)
VALUES
    (:TENANT_ID, 'LEGAL_HOLD_RELEASE', '/runbooks/legal_hold.md', 200,
     'policy_audit_log', :ROW_ID,
     jsonb_build_object(
         'operator', :OPERATOR_EMAIL,
         'release_ticket', :CLOSURE_TICKET,
         'original_hold_apply_audit_id', :SYSTEM_AUDIT_LOG_ID_FROM_APPLY
     ));

UPDATE policy_audit_log
   SET legal_hold_reason = NULL
 WHERE id = :ROW_ID;

SELECT legal_hold_reason FROM policy_audit_log WHERE id = :ROW_ID;
-- Expected: NULL.

COMMIT;
```

After release, the row reverts to normal append-only semantics: it can no longer be UPDATEd or DELETEd, but FK SET NULL cascade (if a referenced `tenant_user` is later deleted) works again.

---

## Interactions with other procedures

### Tenant purge

The tenant-purge runbook (`docs/runbooks/tenant_purge.md`) must be updated to enumerate legal-held rows before starting. If any row in `policy_audit_log` or `baseline_snapshots` for the target tenant has a non-NULL `legal_hold_reason`, the purge cannot proceed until the hold is either released or explicitly overridden via the same DROP TRIGGER → audit → CREATE TRIGGER dance — but releasing a hold to enable a deletion the hold was designed to prevent is itself a legal decision that requires its own approval.

Enumerate before purging:

```sql
SELECT 'policy_audit_log' AS tbl, id::text, legal_hold_reason
  FROM policy_audit_log
 WHERE tenant_id = :TENANT_ID AND legal_hold_reason IS NOT NULL
UNION ALL
SELECT 'baseline_snapshots', id::text, legal_hold_reason
  FROM baseline_snapshots
 WHERE tenant_id = :TENANT_ID AND legal_hold_reason IS NOT NULL;
```

Non-empty result → STOP. Get explicit legal sign-off before proceeding.

### Operator UI affordances

The `(user removed)` affordance — rendered when a tenant_user is hard-deleted and the FK SET NULL cascade nulls out `policy_audit_log.tenant_user_id` — does not apply to held rows. Deleting a tenant_user with held audit history will FAIL at the DB layer; the UI must surface that failure as a clear "this user has retained legal-hold audit history; release the hold first" message rather than a 500.

---

## What this runbook does NOT do

- **Encrypt held rows differently.** The hold is metadata, not at-rest encryption. Field-level encryption is a separate concern.
- **Replicate held rows to a separate immutable store** (S3 Object Lock, etc.). That's a future "WORM tier" enhancement.
- **Notify the affected tenant.** Some preservation orders explicitly forbid notification; some require it. That decision lives outside this runbook.
