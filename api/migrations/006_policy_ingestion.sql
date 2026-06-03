-- Migration 006 — Customer policy ingestion (Piece 46 / task #46)
--
-- Creates the schema for the customer-facing policy ingestion feature:
-- prose-to-Rego conversion, fork-and-tweak overlays, per-tenant Rego buckets,
-- bundle assembly, tenant users with RBAC + MFA, and a full audit log.
--
-- Design reference: docs/policy_ingestion_design.md §7.
--
-- Tier 1 governance columns on customer_policies (control_owner_user_id,
-- review_cadence_days, next_review_due_at, last_reviewed_at, last_reviewed_by)
-- are present in the schema but deferred for runtime use until Phase 7+ per
-- §2.1 (measurable-first sub-principle). They are nullable so the MVP can
-- ignore them without contortions; adding them later via ALTER would be
-- painful enough that paying the storage cost now is the right tradeoff.
--
-- All FKs to tenants(id) cascade on delete — when a tenant is removed,
-- their policies, targets, users, MFA factors, and audit log all go too.
-- Tenant rows are soft-deleted via status='deleted' (see migration 001),
-- so this cascade is the explicit "hard delete" path used by GDPR/CCPA
-- erasure workflows, not by routine offboarding.
--
-- Idempotency: every object uses CREATE ... IF NOT EXISTS or DROP THEN
-- CREATE so the migration is safe to re-apply.

BEGIN;

-- Case-insensitive email comparison without LOWER() everywhere.
CREATE EXTENSION IF NOT EXISTS "citext";


-- ── tenant_users ──────────────────────────────────────────────────────
-- Tenant-scoped human users with RBAC. Distinct from tenant_tokens
-- (which are machine-to-machine credentials issued in migration 001).
-- Defined first so customer_policies can reference it inline.
CREATE TABLE IF NOT EXISTS tenant_users (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email                       citext      NOT NULL,
    display_name                text,
    oidc_subject                text,
    role                        text        NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('account_owner', 'editor', 'viewer')),
    mfa_enrolled                boolean     NOT NULL DEFAULT false,
    mfa_required                boolean     NOT NULL DEFAULT false,
    password_hash               text,
    last_login_at               timestamptz,
    disabled_at                 timestamptz,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_tenant_users_tenant_active
    ON tenant_users (tenant_id)
    WHERE disabled_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_tenant_users_oidc_subject
    ON tenant_users (oidc_subject)
    WHERE oidc_subject IS NOT NULL;

DROP TRIGGER IF EXISTS trg_tenant_users_updated_at ON tenant_users;
CREATE TRIGGER trg_tenant_users_updated_at
    BEFORE UPDATE ON tenant_users
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();


-- ── tenant_user_mfa_factors ───────────────────────────────────────────
-- Per-user MFA enrollment. One user can have multiple factors
-- (TOTP + WebAuthn + backup_codes). Revoked rows are kept for audit.
CREATE TABLE IF NOT EXISTS tenant_user_mfa_factors (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_user_id              uuid        NOT NULL REFERENCES tenant_users(id) ON DELETE CASCADE,
    factor_type                 text        NOT NULL
        CHECK (factor_type IN ('totp', 'webauthn', 'backup_codes')),
    factor_label                text,
    secret_hash                 text        NOT NULL,
    webauthn_credential_id      text,
    enrolled_at                 timestamptz NOT NULL DEFAULT now(),
    last_used_at                timestamptz,
    revoked_at                  timestamptz
);

CREATE INDEX IF NOT EXISTS idx_tenant_user_mfa_factors_user_active
    ON tenant_user_mfa_factors (tenant_user_id)
    WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenant_user_mfa_factors_webauthn_cred
    ON tenant_user_mfa_factors (webauthn_credential_id)
    WHERE webauthn_credential_id IS NOT NULL AND revoked_at IS NULL;


-- ── customer_policies ──────────────────────────────────────────────────
-- One row per uploaded prose document OR fork-and-tweak initiative.
CREATE TABLE IF NOT EXISTS customer_policies (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                        text        NOT NULL,
    framework_bucket            text        NOT NULL,
    policy_source               text        NOT NULL
        CHECK (policy_source IN ('prose_upload', 'forked_overlay', 'customer_original')),
    source_file_storage_key     text,
    source_file_mime            text,
    ir_json                     jsonb,
    parent_standard_ref         text,
    parent_standard_version     text,
    version_semver              text        NOT NULL DEFAULT 'v0.1.0',
    effective_date              date,
    status                      text        NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'in_review', 'published', 'archived')),
    -- Tier 1 governance — present in schema, not exposed in MVP (see header)
    control_owner_user_id       uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,
    review_cadence_days         int         NOT NULL DEFAULT 365,
    next_review_due_at          timestamptz,
    last_reviewed_at            timestamptz,
    last_reviewed_by            uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,
    created_by                  uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_customer_policies_tenant
    ON customer_policies (tenant_id);

CREATE INDEX IF NOT EXISTS idx_customer_policies_tenant_status
    ON customer_policies (tenant_id, status)
    WHERE status != 'archived';

CREATE INDEX IF NOT EXISTS idx_customer_policies_review_due
    ON customer_policies (next_review_due_at)
    WHERE status = 'published' AND next_review_due_at IS NOT NULL;

DROP TRIGGER IF EXISTS trg_customer_policies_updated_at ON customer_policies;
CREATE TRIGGER trg_customer_policies_updated_at
    BEFORE UPDATE ON customer_policies
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();


-- ── customer_policy_targets ───────────────────────────────────────────
-- One row per (customer_policy × target_system) pairing — the
-- "Password Policy → N target Rego files" fan-out from the design.
CREATE TABLE IF NOT EXISTS customer_policy_targets (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_policy_id          uuid        NOT NULL REFERENCES customer_policies(id) ON DELETE CASCADE,
    target_system               text        NOT NULL,
    target_subtype              text,
    rego_storage_key            text        NOT NULL,
    rego_content_sha256         text        NOT NULL,
    generation_method           text        NOT NULL
        CHECK (generation_method IN ('template_mapped', 'llm_fallback', 'customer_authored')),
    confidence_score            real,
    review_status               text        NOT NULL DEFAULT 'pending'
        CHECK (review_status IN ('pending', 'approved', 'rejected')),
    published_in_bundle_sha     text,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (customer_policy_id, target_system, target_subtype)
);

CREATE INDEX IF NOT EXISTS idx_customer_policy_targets_policy
    ON customer_policy_targets (customer_policy_id);

CREATE INDEX IF NOT EXISTS idx_customer_policy_targets_pending_review
    ON customer_policy_targets (customer_policy_id)
    WHERE review_status = 'pending';


-- ── abstract_controls ─────────────────────────────────────────────────
-- Shared across all tenants — the reusable library of control intents.
-- Phase 2 seeds ~10 controls; the table itself has no tenant column.
CREATE TABLE IF NOT EXISTS abstract_controls (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    key                         text        NOT NULL UNIQUE,
    display_name                text        NOT NULL,
    description                 text,
    domain                      text        NOT NULL,
    parameters_schema           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at                  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_abstract_controls_domain
    ON abstract_controls (domain);


-- ── target_mappings ───────────────────────────────────────────────────
-- Shared library: (abstract_control × target_system) → Rego template.
-- Phase 2 seeds ~40 mappings (10 controls × 4 target families).
CREATE TABLE IF NOT EXISTS target_mappings (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    abstract_control_id         uuid        NOT NULL REFERENCES abstract_controls(id) ON DELETE CASCADE,
    target_system               text        NOT NULL,
    target_subtype              text,
    template_engine             text        NOT NULL
        CHECK (template_engine IN ('jinja2', 'llm_prompt')),
    template_body               text        NOT NULL,
    input_contract_schema       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    quality_grade               text        NOT NULL DEFAULT 'library_v1'
        CHECK (quality_grade IN ('library_v1', 'experimental', 'deprecated')),
    created_at                  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (abstract_control_id, target_system, target_subtype)
);

CREATE INDEX IF NOT EXISTS idx_target_mappings_lookup
    ON target_mappings (target_system, target_subtype, quality_grade);


-- ── policy_audit_log ──────────────────────────────────────────────────
-- Append-only event stream of every customer-policy change.
-- bigserial PK (high-volume) — distinct from the uuid PKs above.
CREATE TABLE IF NOT EXISTS policy_audit_log (
    id                          bigserial   PRIMARY KEY,
    tenant_id                   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tenant_user_id              uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,
    customer_policy_id          uuid        REFERENCES customer_policies(id) ON DELETE SET NULL,
    action                      text        NOT NULL,
    details                     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    at                          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_audit_log_tenant_at
    ON policy_audit_log (tenant_id, at DESC);

CREATE INDEX IF NOT EXISTS idx_policy_audit_log_policy_at
    ON policy_audit_log (customer_policy_id, at DESC)
    WHERE customer_policy_id IS NOT NULL;

COMMIT;
