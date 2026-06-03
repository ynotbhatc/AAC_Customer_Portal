-- Migration 008 — Raw policy document uploads (PR 5 of Piece 46)
--
-- One row per uploaded prose document. Stores the raw bytes (bytea)
-- alongside the extracted plaintext. The MVP store; later tiers may
-- swap to S3/Minio/customer-hosted bucket — `customer_policies.source_file_storage_key`
-- holds an opaque key ("pgupload:<uuid>" for this store; a different
-- prefix would route through a different BundleStore impl). No FK
-- between customer_policies.source_file_storage_key and this table
-- on purpose — that's the abstraction boundary.
--
-- Storage budget: typical policy docs are 100KB-2MB; 15MB cap in
-- application code. Postgres TOAST handles this fine without
-- partition tricks for the MVP volume.

BEGIN;

CREATE TABLE IF NOT EXISTS policy_uploads (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    uploaded_by_user_id         uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,
    original_filename           text        NOT NULL,
    sniffed_mime                text        NOT NULL,
    byte_size                   int         NOT NULL,
    byte_sha256                 text        NOT NULL,
    raw_bytes                   bytea       NOT NULL,
    extracted_text              text        NOT NULL,
    extracted_text_chars        int         NOT NULL,
    created_at                  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_uploads_tenant
    ON policy_uploads (tenant_id, created_at DESC);

-- Dedup: re-uploading the exact same file (same bytes, same tenant)
-- is OK at the schema level; the router uses byte_sha256 to short-
-- circuit the parser if it sees a hash it's already processed.
CREATE INDEX IF NOT EXISTS idx_policy_uploads_tenant_sha
    ON policy_uploads (tenant_id, byte_sha256);

COMMIT;
