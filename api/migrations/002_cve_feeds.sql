-- 002_cve_feeds.sql
--
-- CVE event store + run audit for the portal feed adapters (NVD,
-- CISA KEV, and future PSIRTs).
--
-- The matching engine (Piece 7) reads cve_events × tenant_inventory_catalog
-- to compute per-tenant affected sets.
--
-- Idempotent — safe to re-run.

-- ── cve_events ─────────────────────────────────────────────────────────
-- One row per CVE-ID. Updated in place when feeds report changes (NVD
-- lastModified bumps, KEV adds the cve, vendor advisories arrive).
CREATE TABLE IF NOT EXISTS cve_events (
    cve_id              varchar(50) PRIMARY KEY,
    cvss_v3             numeric(3,1),
    cvss_v3_severity    varchar(20),                 -- LOW/MEDIUM/HIGH/CRITICAL
    cvss_v2             numeric(3,1),
    kev_member          boolean      NOT NULL DEFAULT false,
    kev_date_added      date,
    kev_due_date        date,
    kev_required_action text,
    kev_ransomware_use  varchar(20),                 -- Known / Unknown
    published_at        timestamptz,
    last_modified_at    timestamptz,
    vendor              varchar(255),                -- best-effort, may be null
    product             varchar(255),                -- best-effort
    affected_cpes       text[]       NOT NULL DEFAULT ARRAY[]::text[],
    description         text,
    sources             text[]       NOT NULL DEFAULT ARRAY[]::text[],  -- nvd, cisa_kev, vendor:redhat, ...
    raw_nvd             jsonb,
    raw_kev             jsonb,
    received_at         timestamptz  NOT NULL DEFAULT now(),
    updated_at          timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cve_events_severity_published
    ON cve_events (cvss_v3_severity, published_at DESC);

CREATE INDEX IF NOT EXISTS idx_cve_events_kev
    ON cve_events (kev_member) WHERE kev_member = true;

CREATE INDEX IF NOT EXISTS idx_cve_events_last_modified
    ON cve_events (last_modified_at DESC);

CREATE INDEX IF NOT EXISTS idx_cve_events_vendor_product
    ON cve_events (vendor, product);

CREATE INDEX IF NOT EXISTS idx_cve_events_cpes_gin
    ON cve_events USING gin (affected_cpes);

-- ── cve_references ─────────────────────────────────────────────────────
-- External references per CVE: vendor advisories, exploit DBs, patches.
-- Separate table so refs grow over time without rewriting the parent row.
CREATE TABLE IF NOT EXISTS cve_references (
    id          bigserial   PRIMARY KEY,
    cve_id      varchar(50) NOT NULL REFERENCES cve_events(cve_id) ON DELETE CASCADE,
    url         text        NOT NULL,
    source      varchar(50),                       -- e.g. "MISC", "VENDOR", "PATCH"
    tags        text[]      NOT NULL DEFAULT ARRAY[]::text[],  -- ["Patch","Vendor Advisory"]
    added_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cve_id, url)
);

CREATE INDEX IF NOT EXISTS idx_cve_refs_cve ON cve_references (cve_id);

-- ── feed_runs ──────────────────────────────────────────────────────────
-- One row per attempt to pull a feed. Used by the admin /feeds/runs
-- endpoint and by feed adapters to resume from `cursor_after`.
CREATE TABLE IF NOT EXISTS feed_runs (
    id              bigserial   PRIMARY KEY,
    source          varchar(50) NOT NULL,           -- 'nvd', 'cisa_kev', 'vendor:redhat'
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    status          varchar(20) NOT NULL DEFAULT 'running',
    cursor_before   timestamptz,                    -- value of cursor_after on prior run
    cursor_after    timestamptz,                    -- last_modified watermark advanced
    rows_seen       integer     NOT NULL DEFAULT 0,
    rows_added      integer     NOT NULL DEFAULT 0,
    rows_updated    integer     NOT NULL DEFAULT 0,
    http_status     integer,
    error_message   text,
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    CHECK (status IN ('running','success','failed','partial'))
);

CREATE INDEX IF NOT EXISTS idx_feed_runs_source_started
    ON feed_runs (source, started_at DESC);

-- ── updated_at trigger for cve_events ──────────────────────────────────
DROP TRIGGER IF EXISTS trg_cve_events_updated_at ON cve_events;
CREATE TRIGGER trg_cve_events_updated_at
    BEFORE UPDATE ON cve_events
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
