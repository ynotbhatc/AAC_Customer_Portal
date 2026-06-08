-- Remediation items + four-eyes approval state machine.
--
-- Frontend (`/api/remediation`) was a 501 stub from PR #42. This
-- migration ships the real backing table.
--
-- State machine
-- =============
--
-- New items land in `open` (created when an assessment fails a
-- control AND we materialize it for tenant action). The lifecycle:
--
--     open ─assign──> in_progress ──submit──> pending_approval
--                          ▲                       │
--                          │                       ├──approve──> approved
--                          │                       │
--                          └─reject (audited)──────┘
--
-- Four-eyes rule
-- ==============
--
-- approve transition requires `approved_by` to be DIFFERENT from
-- the actor who submitted the item for approval
-- (`requested_approval_by`). The CHECK constraint enforces this
-- at the DB level so the rule can't be silently bypassed by a
-- bug in the router.
--
-- Audit
-- =====
--
-- Every transition writes a row to system_audit_log via the
-- AuditMiddleware (PRs #47 + #50). The router additionally writes
-- a remediation-specific row to remediation_history (this
-- migration) capturing old_status → new_status with the actor.
-- The two trails serve different audiences: system_audit_log for
-- security investigation across the whole API, remediation_history
-- for compliance-officer-friendly per-item timelines.

BEGIN;

-- ── remediation_items ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS remediation_items (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Origin of the item: which host + framework + control failed
    hostname                text        NOT NULL,
    framework               text        NOT NULL,
    control_id              text        NOT NULL,
    description             text        NOT NULL,
    severity                text        NOT NULL CHECK (severity IN ('critical','high','medium','low')),

    -- State machine
    status                  text        NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open','in_progress','pending_approval','approved')),

    -- Assignment
    assigned_to             uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,

    -- Approval request (set when status transitions to pending_approval)
    requested_approval_at   timestamptz NULL,
    requested_approval_by   uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,

    -- Approval grant (set when status transitions to approved)
    approved_at             timestamptz NULL,
    approved_by             uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,
    approval_notes          text        NULL,

    -- Bookkeeping
    created_at              timestamptz NOT NULL DEFAULT now(),
    created_by              uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,
    updated_at              timestamptz NOT NULL DEFAULT now(),
    updated_by              uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,

    -- Four-eyes invariant: the approver cannot be the requester.
    -- NULL on either side means "not yet at this state" — those rows
    -- pass the check trivially.
    CONSTRAINT four_eyes_separate_actors
        CHECK (
            approved_by IS NULL
            OR requested_approval_by IS NULL
            OR approved_by <> requested_approval_by
        )
);

-- Tenant-scoped listings + sort by created_at DESC
CREATE INDEX IF NOT EXISTS idx_remediation_items_tenant_created
    ON remediation_items (tenant_id, created_at DESC);

-- Status board view (open + in_progress + pending_approval) per tenant
CREATE INDEX IF NOT EXISTS idx_remediation_items_tenant_status
    ON remediation_items (tenant_id, status, created_at DESC)
    WHERE status IN ('open', 'in_progress', 'pending_approval');

-- Per-host drill-down
CREATE INDEX IF NOT EXISTS idx_remediation_items_hostname
    ON remediation_items (tenant_id, hostname, created_at DESC);

-- ── remediation_history ──────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS remediation_history (
    id              bigserial   PRIMARY KEY,
    item_id         uuid        NOT NULL REFERENCES remediation_items(id) ON DELETE CASCADE,
    actor_id        uuid        REFERENCES tenant_users(id) ON DELETE SET NULL,
    transition      text        NOT NULL CHECK (transition IN ('create','assign','submit','approve','reject')),
    from_status     text        NULL,
    to_status       text        NOT NULL,
    notes           text        NULL,
    at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_remediation_history_item_at
    ON remediation_history (item_id, at DESC);

COMMIT;
