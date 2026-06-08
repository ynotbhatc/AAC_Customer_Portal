-- System-wide API audit log.
--
-- policy_audit_log (006) captures policy lifecycle events specifically.
-- This table captures EVERY mutating API call (POST/PUT/PATCH/DELETE)
-- across every router, so compliance auditors can answer "who did
-- what to what resource when, and what was the outcome" without
-- having to stitch together logs.
--
-- Writes are made by `src/core/audit_middleware.py` from a background
-- task, so a failed audit insert does not break the API response.
-- That trade-off is deliberate: missing the occasional audit row is
-- preferable to a 500 on the actual operation. The middleware also
-- logs to the application logger on insert failure so the gap is
-- observable.

BEGIN;

CREATE TABLE IF NOT EXISTS system_audit_log (
    id              bigserial   PRIMARY KEY,
    -- Both nullable because (a) anonymous calls that get rejected at
    -- auth still produce audit rows (security signal), and (b) some
    -- admin-token endpoints don't carry a tenant context.
    tenant_id       uuid        REFERENCES tenants(id) ON DELETE SET NULL,
    tenant_user_id  uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,
    -- HTTP fingerprint of the request.
    method          text        NOT NULL,
    path            text        NOT NULL,
    status_code     int         NOT NULL,
    -- Identifies the resource the action was against, when the
    -- framework can determine it. method+path is the floor; this is
    -- the icing that makes resource-history queries cheap.
    resource_type   text        NULL,
    resource_id     text        NULL,
    -- Correlation with the structured logs (asgi-correlation-id's
    -- X-Request-ID). Lets an auditor jump from this row to the
    -- application log line for that request.
    correlation_id  text        NULL,
    client_ip       inet        NULL,
    user_agent      text        NULL,
    -- Free-form bag for endpoint-specific context (request body
    -- snippet, before/after for state changes, etc.). Endpoints
    -- attach via the explicit record_audit() helper.
    details         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    at              timestamptz NOT NULL DEFAULT now()
);

-- Common query: "show me everything for tenant X in the last N days"
CREATE INDEX IF NOT EXISTS idx_system_audit_log_tenant_at
    ON system_audit_log (tenant_id, at DESC)
    WHERE tenant_id IS NOT NULL;

-- Per-resource history: "what happened to /remediation/abc-123?"
CREATE INDEX IF NOT EXISTS idx_system_audit_log_resource
    ON system_audit_log (resource_type, resource_id, at DESC)
    WHERE resource_type IS NOT NULL AND resource_id IS NOT NULL;

-- Security investigation: "all 401/403/4xx from a single IP"
CREATE INDEX IF NOT EXISTS idx_system_audit_log_ip_status
    ON system_audit_log (client_ip, status_code, at DESC)
    WHERE client_ip IS NOT NULL;

-- Correlation-id lookup for app-log → audit-log jumps
CREATE INDEX IF NOT EXISTS idx_system_audit_log_corr
    ON system_audit_log (correlation_id)
    WHERE correlation_id IS NOT NULL;

COMMIT;
