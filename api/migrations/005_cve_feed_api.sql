-- 005_cve_feed_api.sql
--
-- Portal-side vendor-remediation store. Used by the per-tenant feed
-- API to ship "and here's how YOUR distro patches this" alongside the
-- raw CVE.
--
-- v1 populates this only from cve_references that look like vendor
-- advisories (RHSA-*, USN-*, KB*, etc.) via a future PSIRT adapter.
-- Schema is here now so the feed router can join against it.
--
-- Idempotent.

CREATE TABLE IF NOT EXISTS cve_vendor_remediations (
    id                  bigserial   PRIMARY KEY,
    cve_id              varchar(50) NOT NULL REFERENCES cve_events(cve_id) ON DELETE CASCADE,
    vendor_id           bigint      NOT NULL REFERENCES vendors(id) ON DELETE CASCADE,
    vendor_advisory_id  varchar(100),
    fix_version         varchar(100),
    patch_url           text,
    patch_description   text,
    available_at        timestamptz,
    received_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cve_id, vendor_id, vendor_advisory_id)
);

CREATE INDEX IF NOT EXISTS idx_cve_vendor_rem_cve
    ON cve_vendor_remediations (cve_id);

CREATE INDEX IF NOT EXISTS idx_cve_vendor_rem_vendor
    ON cve_vendor_remediations (vendor_id);
