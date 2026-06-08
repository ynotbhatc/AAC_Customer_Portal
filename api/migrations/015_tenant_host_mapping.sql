-- Tenant ↔ host mapping for compliance read-scoping.
--
-- Background: compliance_results lives in the compliance DB (read via
-- the compliance_reader pool) and the AAC assessment pipeline writes
-- to it without any tenant_id column today. To enforce multi-tenant
-- read scoping at the portal layer without coupling to the assessment
-- pipeline's schema, we own the mapping here in the portal DB.
--
-- Read path: the compliance router fetches this tenant's allowed
-- hostnames first, then filters compliance_results queries with
-- `WHERE hostname = ANY($1)`. Single round-trip on the portal pool
-- + one filtered query on the compliance pool. See
-- src/core/tenant_scope.py.
--
-- One host can map to multiple tenants (some MSP-style deployments
-- assess shared infrastructure for multiple customers). The
-- composite PRIMARY KEY enforces uniqueness of the triple, not just
-- the hostname.

BEGIN;

CREATE TABLE IF NOT EXISTS tenant_host_mapping (
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname     text        NOT NULL,
    -- Optional: restrict the mapping to specific frameworks for this
    -- host. NULL means "all frameworks for this host". Useful when a
    -- host is shared across tenants but evaluated against different
    -- benchmarks per customer.
    framework    text        NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,
    PRIMARY KEY (tenant_id, hostname, COALESCE(framework, ''))
);

-- Fast lookup of "which hostnames does this tenant see?"
CREATE INDEX IF NOT EXISTS idx_tenant_host_mapping_tenant
    ON tenant_host_mapping (tenant_id);

-- Reverse lookup: "which tenants see this hostname?" (operator triage)
CREATE INDEX IF NOT EXISTS idx_tenant_host_mapping_hostname
    ON tenant_host_mapping (hostname);

COMMIT;
