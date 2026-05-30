-- 003_classification.sql
--
-- Operator-curated taxonomy + per-CVE tagging. The matching engine
-- (Piece 7) uses these tags to filter the per-tenant feed: tenant
-- enrolls in N buckets, gets only CVEs tagged with those buckets.
--
-- Tag rows carry a confidence score and a method string so manual
-- operator overrides survive re-classifications by the auto worker.
--
-- Idempotent — safe to re-run.

-- ── buckets ────────────────────────────────────────────────────────────
-- Coarse-grained categories the customer enrolls in.
CREATE TABLE IF NOT EXISTS buckets (
    id           bigserial   PRIMARY KEY,
    key          varchar(50) NOT NULL UNIQUE,        -- 'rhel','windows_server','ot_scada'
    display_name varchar(150) NOT NULL,
    description  text,
    bucket_type  varchar(30) NOT NULL DEFAULT 'os',  -- os|app|middleware|network|ot|cloud|container|runtime
    sort_order   integer     NOT NULL DEFAULT 100,
    active       boolean     NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_buckets_active_type
    ON buckets (active, bucket_type, sort_order);

-- ── vendors ────────────────────────────────────────────────────────────
-- Canonical vendor catalog. The aliases and CPE keys are what the
-- classifier matches against; advisory_id_pattern lets us recognize a
-- vendor advisory reference (RHSA, USN, MSRC) in cve_references.
CREATE TABLE IF NOT EXISTS vendors (
    id                  bigserial   PRIMARY KEY,
    key                 varchar(100) NOT NULL UNIQUE,
    display_name        varchar(255) NOT NULL,
    aliases             text[]      NOT NULL DEFAULT ARRAY[]::text[],
    cpe_vendor_keys     text[]      NOT NULL DEFAULT ARRAY[]::text[],  -- matches cpe:2.3:?:<this>:...
    advisory_id_pattern text,                                          -- POSIX regex
    psirt_url           text,
    active              boolean     NOT NULL DEFAULT true,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vendors_aliases_gin
    ON vendors USING gin (aliases);

CREATE INDEX IF NOT EXISTS idx_vendors_cpe_keys_gin
    ON vendors USING gin (cpe_vendor_keys);

-- ── bucket_vendor_links ────────────────────────────────────────────────
-- Many-to-many: a vendor is associated with one or more buckets.
-- (Microsoft → windows_server + application; Red Hat → rhel + middleware;
-- Apache → middleware + application.)
CREATE TABLE IF NOT EXISTS bucket_vendor_links (
    bucket_id bigint NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    vendor_id bigint NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    PRIMARY KEY (bucket_id, vendor_id)
);

-- ── cve_bucket_tags ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_bucket_tags (
    cve_id     varchar(50) NOT NULL REFERENCES cve_events(cve_id) ON DELETE CASCADE,
    bucket_id  bigint      NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
    confidence smallint    NOT NULL DEFAULT 80,
    method     varchar(30) NOT NULL DEFAULT 'auto',   -- auto|operator|rule:<name>
    tagged_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, bucket_id),
    CHECK (confidence BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_cve_bucket_tags_bucket
    ON cve_bucket_tags (bucket_id);

-- ── cve_vendor_tags ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_vendor_tags (
    cve_id     varchar(50) NOT NULL REFERENCES cve_events(cve_id) ON DELETE CASCADE,
    vendor_id  bigint      NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    confidence smallint    NOT NULL DEFAULT 80,
    method     varchar(30) NOT NULL DEFAULT 'auto',
    tagged_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, vendor_id),
    CHECK (confidence BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_cve_vendor_tags_vendor
    ON cve_vendor_tags (vendor_id);
