-- Migration 013 — Baseline snapshots
--
-- A baseline snapshot is a point-in-time capture of one tenant's
-- compliance evaluation results. The bridge runs OPA against the
-- current signed bundle and POSTs the aggregate to this table; the
-- portal stores it as immutable history.
--
-- "Are we drifting from baseline?" becomes answerable by comparing
-- the most recent snapshot's `summary` against any prior one. Later
-- PRs will add per-host / per-control detail in a second table.

BEGIN;

CREATE TABLE IF NOT EXISTS baseline_snapshots (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Which bundle the bridge had loaded into OPA when it produced
    -- these results. NOT a FK to policy_bundles.bundle_sha256 because
    -- the bridge may sit on an older bundle than the portal's current
    -- row, and we want the snapshot to be honest about what was
    -- actually evaluated.
    bundle_sha256       text        NOT NULL,

    captured_at         timestamptz NOT NULL DEFAULT now(),
    captured_by_user_id uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,

    -- Free-text customer label, e.g. "Q4 2026 baseline" / "pre-prod
    -- cutover" / "post-incident IR-014". Optional.
    label               text,

    -- Aggregate evaluation stats. Schema:
    --   {
    --     "host_count": int,
    --     "total_evaluations": int,
    --     "passing": int,
    --     "failing": int,
    --     "errors": int,
    --     "by_framework": {
    --       "<framework_bucket>": {"passing": int, "failing": int},
    --       ...
    --     }
    --   }
    -- The bridge is the contract owner; the portal stores opaque.
    summary             jsonb       NOT NULL,

    -- How the snapshot was created — primarily for audit trails.
    -- 'bridge_push' is the normal path; 'manual' is the operator UI
    -- importing a JSON payload (useful for backfills + testing).
    source              text        NOT NULL CHECK (source IN ('bridge_push', 'manual', 'scheduled'))
);

CREATE INDEX IF NOT EXISTS idx_baseline_snapshots_tenant_at
    ON baseline_snapshots (tenant_id, captured_at DESC);

COMMIT;
