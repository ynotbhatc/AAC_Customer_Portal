-- 001_cve_intelligence.sql
--
-- Portal-side schema for CVE Intelligence. Lives in the operator's own
-- `aac_portal` PostgreSQL database (separate from any customer's
-- compliance database).
--
-- This migration adds the tenant + token tables that Piece 4 needs.
-- Later pieces will add cve_events, cve_artifacts, tenant_inventory_catalog,
-- bucket/vendor classification tables.
--
-- Idempotent — safe to re-run.

-- ── extensions ─────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()

-- ── tenants ────────────────────────────────────────────────────────────
-- One row per customer. Identity, tier, where their AAC bridge lives.
CREATE TABLE IF NOT EXISTS tenants (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name          varchar(255) NOT NULL,
    contact_email         varchar(255),
    tier                  varchar(30)  NOT NULL DEFAULT 'standard',
    aac_bridge_url        text,                       -- e.g. https://aac.acme.com:8005
    aac_bridge_verify_ssl boolean      NOT NULL DEFAULT true,
    status                varchar(30)  NOT NULL DEFAULT 'pending',
    notes                 text,
    created_at            timestamptz  NOT NULL DEFAULT now(),
    updated_at            timestamptz  NOT NULL DEFAULT now(),
    CHECK (tier   IN ('free','standard','premium','airgapped')),
    CHECK (status IN ('pending','active','suspended','deleted'))
);

CREATE INDEX IF NOT EXISTS idx_tenants_status
    ON tenants (status) WHERE status != 'deleted';

-- ── tenant_tokens ──────────────────────────────────────────────────────
-- Bearer credentials for the mutual pull APIs. Each tenant can have
-- multiple active tokens (rotation, separate keys for inventory pull vs.
-- CVE feed pull). token_secret is stored ONLY as a bcrypt hash; the
-- plaintext is shown to the operator exactly once at creation time.
CREATE TABLE IF NOT EXISTS tenant_tokens (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    token_id            text        NOT NULL UNIQUE,
    token_secret_hash   text        NOT NULL,
    description         text,
    scopes              text[]      NOT NULL DEFAULT ARRAY['inventory_pull','cve_feed']::text[],
    created_at          timestamptz NOT NULL DEFAULT now(),
    created_by          varchar(255),
    last_used_at        timestamptz,
    last_used_from_ip   inet,
    revoked_at          timestamptz,
    revoked_reason      text
);

CREATE INDEX IF NOT EXISTS idx_tenant_tokens_active
    ON tenant_tokens (tenant_id) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tenant_tokens_token_id
    ON tenant_tokens (token_id);

-- ── tenant_inventory_catalog (Piece 7 will populate) ───────────────────
-- Cached copy of each tenant's AAC inventory_catalog, pulled nightly via
-- the AAC Portal Bridge. Schema is provisional; the matching engine in
-- Piece 7 may evolve the columns.
CREATE TABLE IF NOT EXISTS tenant_inventory_catalog (
    id                bigserial   PRIMARY KEY,
    tenant_id         uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vendor            varchar(255) NOT NULL,
    product           varchar(255) NOT NULL,
    version           varchar(100) NOT NULL,
    cpe               text,
    host_count        integer,
    source            varchar(20)  NOT NULL DEFAULT 'auto',
    aac_first_seen_at timestamptz,
    aac_last_seen_at  timestamptz,
    pulled_at         timestamptz  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, vendor, product, version, source)
);

CREATE INDEX IF NOT EXISTS idx_tic_tenant
    ON tenant_inventory_catalog (tenant_id);

CREATE INDEX IF NOT EXISTS idx_tic_cpe
    ON tenant_inventory_catalog (cpe) WHERE cpe IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tic_vendor_product
    ON tenant_inventory_catalog (vendor, product);

-- ── tenant_pull_runs ───────────────────────────────────────────────────
-- One row per attempt to pull the inventory catalog from a tenant's AAC
-- bridge. Audit trail; "last run was X minutes ago, returned 412 rows".
CREATE TABLE IF NOT EXISTS tenant_pull_runs (
    id              bigserial   PRIMARY KEY,
    tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    status          varchar(30) NOT NULL DEFAULT 'running',
    rows_pulled     integer,
    bridge_version  varchar(50),
    http_status     integer,
    error_message   text,
    CHECK (status IN ('running','success','failed','partial'))
);

CREATE INDEX IF NOT EXISTS idx_pull_runs_tenant_started
    ON tenant_pull_runs (tenant_id, started_at DESC);

-- ── updated_at trigger ─────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION touch_updated_at()
RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tenants_updated_at ON tenants;
CREATE TRIGGER trg_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
