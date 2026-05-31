-- 004_matching.sql
--
-- Per-tenant enrollment + matching engine state. Adds the tables the
-- inventory puller and matcher write to, plus a column on tenant_tokens
-- that holds the plaintext secret the portal needs for outbound calls
-- to the customer's AAC bridge.
--
-- ⚠ Plaintext token storage caveat
--   `tenant_tokens.token_secret_plaintext` holds the same secret as the
--   bcrypt hash but in plaintext, because the portal needs it to
--   authenticate OUTBOUND requests to the customer's AAC bridge. For v1
--   (no customers yet) it is stored plaintext; production must wrap
--   this with Fernet/KMS encryption-at-rest. Tracked as a follow-up.
--
-- Idempotent — safe to re-run.

-- ── tenant_tokens: add outbound-credential column ──────────────────────
ALTER TABLE tenant_tokens
    ADD COLUMN IF NOT EXISTS token_secret_plaintext text;

COMMENT ON COLUMN tenant_tokens.token_secret_plaintext IS
  'Plaintext secret used by the portal for OUTBOUND calls to the tenant''s AAC bridge. '
  'Bcrypt hash in token_secret_hash is still used for INBOUND verification. '
  'TODO: wrap with Fernet/KMS before any production customer.';

-- ── tenant_enrollments ─────────────────────────────────────────────────
-- Which buckets a tenant cares about. Coarse-grained.
CREATE TABLE IF NOT EXISTS tenant_enrollments (
    tenant_id   uuid    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bucket_id   bigint  NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    enrolled_by varchar(255),
    PRIMARY KEY (tenant_id, bucket_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_enrollments_tenant
    ON tenant_enrollments (tenant_id);

-- ── tenant_vendor_subscriptions ────────────────────────────────────────
-- Finer-grained: tenant subscribes to a specific vendor regardless of
-- bucket. Used to opt-in to a single vendor without enrolling in a
-- whole bucket, or to opt-out (allow=false) of a vendor that comes
-- along with a bucket they're enrolled in.
CREATE TABLE IF NOT EXISTS tenant_vendor_subscriptions (
    tenant_id   uuid    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    vendor_id   bigint  NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    allow       boolean NOT NULL DEFAULT true,
    subscribed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, vendor_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_vendor_subs_tenant
    ON tenant_vendor_subscriptions (tenant_id);

-- ── tenant_filter_preferences ──────────────────────────────────────────
-- Single-row-per-tenant knobs. Severity threshold, KEV pass-through,
-- whether tag-only (no inventory hit) matches are delivered.
CREATE TABLE IF NOT EXISTS tenant_filter_preferences (
    tenant_id              uuid    PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    min_severity           varchar(20) NOT NULL DEFAULT 'MEDIUM',
    deliver_kev_regardless boolean NOT NULL DEFAULT true,
    deliver_tag_only       boolean NOT NULL DEFAULT false,
    auto_apply_kev         boolean NOT NULL DEFAULT false,
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CHECK (min_severity IN ('LOW','MEDIUM','HIGH','CRITICAL','NONE'))
);

-- ── tenant_cve_matches ─────────────────────────────────────────────────
-- The output of the matcher. One row per (tenant, cve) that survived
-- enrollment + severity + inventory filtering. Drives the customer-
-- facing /api/portal/v1/tenants/<id>/cves feed (Piece 8).
CREATE TABLE IF NOT EXISTS tenant_cve_matches (
    id                  bigserial   PRIMARY KEY,
    tenant_id           uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    cve_id              varchar(50) NOT NULL REFERENCES cve_events(cve_id) ON DELETE CASCADE,
    severity            varchar(20),
    kev_member          boolean     NOT NULL DEFAULT false,
    matched_buckets     text[]      NOT NULL DEFAULT ARRAY[]::text[],
    matched_vendors     text[]      NOT NULL DEFAULT ARRAY[]::text[],
    affected_products   jsonb       NOT NULL DEFAULT '[]'::jsonb,   -- [{vendor,product,version,host_count}]
    inventory_hits      integer     NOT NULL DEFAULT 0,
    match_method        varchar(30) NOT NULL,                       -- cpe | vendor_product | tag_only
    delivered_at        timestamptz,
    acknowledged_at     timestamptz,
    suppressed_at       timestamptz,
    suppression_reason  text,
    matched_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_matches_tenant_undelivered
    ON tenant_cve_matches (tenant_id) WHERE delivered_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_matches_tenant_matched_at
    ON tenant_cve_matches (tenant_id, matched_at DESC);

CREATE INDEX IF NOT EXISTS idx_matches_cve
    ON tenant_cve_matches (cve_id);

-- ── match_runs ─────────────────────────────────────────────────────────
-- Per-tenant per-attempt audit of matcher invocations.
CREATE TABLE IF NOT EXISTS match_runs (
    id              bigserial   PRIMARY KEY,
    tenant_id       uuid        REFERENCES tenants(id) ON DELETE CASCADE,  -- nullable = all-tenants run
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    status          varchar(20) NOT NULL DEFAULT 'running',
    candidates_seen integer     NOT NULL DEFAULT 0,
    rows_added      integer     NOT NULL DEFAULT 0,
    rows_updated    integer     NOT NULL DEFAULT 0,
    error_message   text,
    CHECK (status IN ('running','success','failed','partial'))
);

CREATE INDEX IF NOT EXISTS idx_match_runs_started ON match_runs (started_at DESC);
