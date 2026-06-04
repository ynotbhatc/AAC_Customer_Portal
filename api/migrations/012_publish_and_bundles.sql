-- Migration 012 — Publish flow + signed bundle delivery (PR 9 of Piece 46)
--
-- Three parts:
--
--   1. customer_policies.published_at + immutability guard.
--      Once a policy is published, edits become a republish (version
--      bump + new bundle), not an in-place mutation. Auditors can ask
--      "what was in tenant X's bundle on date Y" and get a stable
--      answer.
--
--   2. customer_policy_targets.published_in_bundle_sha already exists
--      from migration 006; this PR is the first one that populates it.
--
--   3. policy_bundles — per-tenant bundle history. Stores the raw
--      bundle bytes (gzipped tar produced by `opa build`), an
--      ed25519-signed JWS envelope of the bundle SHA, and a manifest
--      jsonb summarising what's inside. The AAC bridge polls a
--      tenant-scoped endpoint and gets back the bytes + envelope; it
--      verifies the envelope against the embedded portal public key
--      before loading the bundle.
--
-- Tenant token scopes are extended elsewhere; the schema doesn't
-- enforce scope names.

BEGIN;


-- ── customer_policies: publish metadata + immutability guard ───────────
ALTER TABLE customer_policies
    ADD COLUMN IF NOT EXISTS published_at timestamptz;

ALTER TABLE customer_policies
    ADD COLUMN IF NOT EXISTS published_by uuid REFERENCES tenant_users(id) ON DELETE SET NULL;


-- A published policy may NOT be edited in place; only its status (e.g.
-- promoting from published → archived) and reviewed-by columns may change.
-- Republishing flows must INSERT a new customer_policies row with a
-- bumped version_semver and a different id. Hard-coded list of columns
-- the guard considers "content."
CREATE OR REPLACE FUNCTION enforce_published_immutability()
RETURNS trigger AS $$
BEGIN
    IF OLD.status = 'published' AND NEW.status = 'published' THEN
        IF NEW.name <> OLD.name
           OR NEW.framework_bucket <> OLD.framework_bucket
           OR NEW.ir_json IS DISTINCT FROM OLD.ir_json
           OR NEW.source_file_storage_key IS DISTINCT FROM OLD.source_file_storage_key
           OR NEW.version_semver <> OLD.version_semver
        THEN
            RAISE EXCEPTION
                'customer_policies %: cannot edit a published policy in place '
                '(republish via a new row with a bumped version_semver)',
                OLD.id
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_customer_policies_published_immutable ON customer_policies;
CREATE TRIGGER trg_customer_policies_published_immutable
    BEFORE UPDATE ON customer_policies
    FOR EACH ROW EXECUTE FUNCTION enforce_published_immutability();


-- ── policy_bundles ────────────────────────────────────────────────────
-- One row per (tenant × bundle build). The current bundle for a tenant
-- is the most recently-created row; historical rows are kept so the
-- AAC bridge can pin to a specific bundle_sha during rollout/rollback.
--
-- bundle_bytes are the gzipped tar produced by `opa build` — the
-- AAC bridge consumes them with `opa run --bundle` directly, no
-- format translation.
--
-- signed_envelope_bytes is the JWS-wrapped ed25519 signature of the
-- bundle_sha256. The bridge embeds the portal's public key and
-- verifies the envelope before loading the bundle into OPA.
CREATE TABLE IF NOT EXISTS policy_bundles (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    bundle_sha256               text        NOT NULL,
    bundle_bytes                bytea       NOT NULL,
    bundle_byte_size            int         NOT NULL,
    signed_envelope_bytes       bytea       NOT NULL,
    signing_key_id              text        NOT NULL,
    manifest                    jsonb       NOT NULL,
    target_count                int         NOT NULL,
    customer_policy_ids         uuid[]      NOT NULL,
    excluded_target_count       int         NOT NULL DEFAULT 0,
    excluded_targets_log        jsonb       NOT NULL DEFAULT '[]'::jsonb,
    built_at                    timestamptz NOT NULL DEFAULT now(),
    built_by_user_id            uuid        REFERENCES tenant_users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_policy_bundles_tenant_latest
    ON policy_bundles (tenant_id, built_at DESC);

-- Allow direct lookup by sha for the "give me bundle X" rollback flow.
CREATE INDEX IF NOT EXISTS idx_policy_bundles_tenant_sha
    ON policy_bundles (tenant_id, bundle_sha256);

COMMIT;
