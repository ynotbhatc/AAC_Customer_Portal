"""Migration 018 — per-row legal-hold semantics on policy_audit_log
and baseline_snapshots.

The trigger logic gets denser in this migration: the rules from
migration 017 still apply for rows with `legal_hold_reason IS NULL`,
but the legal-hold-active branch is stricter (ALL columns frozen
except legal_hold_reason itself).

The shape we want to pin:

  legal_hold_reason | UPDATE allowed?               | DELETE allowed?
  ──────────────────┼───────────────────────────────┼────────────────
  NULL              | FK SET NULL cascade OR        | no
                    | setting legal_hold_reason     |
  non-NULL          | ONLY changing                 | no
                    | legal_hold_reason             |
"""
from __future__ import annotations

import asyncpg
import bcrypt
import pytest
import pytest_asyncio


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest_asyncio.fixture(loop_scope="session")
async def seeded(pg_pool):
    """One tenant + one user + one policy + one audit row + one
    baseline. The audit and baseline rows are NOT on hold yet —
    each test toggles legal_hold_reason as needed.
    """
    async with pg_pool.acquire() as conn:
        tenant_id = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Legal Hold Test Tenant",
        )
        user_id = await conn.fetchval(
            """INSERT INTO tenant_users
                  (tenant_id, email, role, mfa_required, password_hash)
               VALUES ($1, $2, 'account_owner', false, $3) RETURNING id""",
            tenant_id, "lh-user@example.com",
            bcrypt.hashpw(b"x" * 24, bcrypt.gensalt(rounds=4)).decode(),
        )
        policy_id = await conn.fetchval(
            """
            INSERT INTO customer_policies
                (tenant_id, name, framework_bucket, policy_source, status,
                 ir_json, version_semver)
            VALUES ($1, 'Test policy', 'iso27001', 'prose_upload',
                    'draft', '{}'::jsonb, '0.1.0')
            RETURNING id
            """,
            tenant_id,
        )
        audit_id = await conn.fetchval(
            """
            INSERT INTO policy_audit_log
                (tenant_id, tenant_user_id, customer_policy_id, action, details)
            VALUES ($1, $2, $3, 'uploaded', '{}'::jsonb)
            RETURNING id
            """,
            tenant_id, user_id, policy_id,
        )
        baseline_id = await conn.fetchval(
            """
            INSERT INTO baseline_snapshots
                (tenant_id, bundle_sha256, label, summary, source)
            VALUES ($1, $2, 'pre-test', '{"host_count": 0, "total_evaluations": 0,
                    "passing": 0, "failing": 0, "errors": 0, "by_framework": {}}'::jsonb,
                    'manual')
            RETURNING id
            """,
            tenant_id, "a" * 64,
        )
    return {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "policy_id": policy_id,
        "audit_id": audit_id,
        "baseline_id": baseline_id,
    }


# ── Default state: legal_hold_reason IS NULL ────────────────────────


async def test_default_legal_hold_is_null(pg_pool, seeded):
    async with pg_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT legal_hold_reason FROM policy_audit_log WHERE id = $1",
            seeded["audit_id"],
        )
    assert row["legal_hold_reason"] is None


async def test_fk_cascade_still_works_when_not_on_hold(pg_pool, seeded):
    """Migration 017's FK SET NULL allowance must still fire when the
    row is not on legal hold."""
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "DELETE FROM tenant_users WHERE id = $1", seeded["user_id"]
        )
        row = await conn.fetchrow(
            "SELECT tenant_user_id FROM policy_audit_log WHERE id = $1",
            seeded["audit_id"],
        )
    assert row["tenant_user_id"] is None


# ── Setting legal hold ──────────────────────────────────────────────


async def test_can_set_legal_hold_reason(pg_pool, seeded):
    """Setting a hold is an allowed mutation while OLD has NULL."""
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = $1 WHERE id = $2",
            "SEC-2026-014 preservation order",
            seeded["audit_id"],
        )
        row = await conn.fetchrow(
            "SELECT legal_hold_reason FROM policy_audit_log WHERE id = $1",
            seeded["audit_id"],
        )
    assert row["legal_hold_reason"] == "SEC-2026-014 preservation order"


async def test_setting_hold_alongside_other_change_is_blocked(pg_pool, seeded):
    """The transition NULL → non-NULL is allowed, but a SET clause
    that ALSO changes another column is not — operators must do the
    hold-set in isolation."""
    async with pg_pool.acquire() as conn:
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await conn.execute(
                """
                UPDATE policy_audit_log
                   SET legal_hold_reason = 'hold reason',
                       action = 'tampered'
                 WHERE id = $1
                """,
                seeded["audit_id"],
            )


# ── On hold: every other change is blocked ──────────────────────────


async def test_fk_cascade_is_blocked_when_on_hold(pg_pool, seeded):
    """A row on legal hold cannot have its actor erased — even via FK
    SET NULL cascade. The whole tenant_users DELETE must fail."""
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = $1 WHERE id = $2",
            "active SEC inquiry — actor identity must be preserved",
            seeded["audit_id"],
        )
        with pytest.raises(asyncpg.exceptions.CheckViolationError) as exc:
            await conn.execute(
                "DELETE FROM tenant_users WHERE id = $1", seeded["user_id"]
            )
    assert "legal hold" in str(exc.value).lower()


async def test_direct_update_is_blocked_when_on_hold(pg_pool, seeded):
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = 'reason' WHERE id = $1",
            seeded["audit_id"],
        )
        with pytest.raises(asyncpg.exceptions.CheckViolationError) as exc:
            await conn.execute(
                "UPDATE policy_audit_log SET action = 'tampered' WHERE id = $1",
                seeded["audit_id"],
            )
    assert "legal hold" in str(exc.value).lower()


async def test_delete_is_blocked_when_on_hold(pg_pool, seeded):
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = 'reason' WHERE id = $1",
            seeded["audit_id"],
        )
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await conn.execute(
                "DELETE FROM policy_audit_log WHERE id = $1",
                seeded["audit_id"],
            )


# ── Clearing legal hold ─────────────────────────────────────────────


async def test_can_clear_legal_hold_reason(pg_pool, seeded):
    """A held row can be released by setting legal_hold_reason to
    NULL. This is the documented operator path when a legal matter
    closes."""
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = 'a' WHERE id = $1",
            seeded["audit_id"],
        )
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = NULL WHERE id = $1",
            seeded["audit_id"],
        )
        row = await conn.fetchrow(
            "SELECT legal_hold_reason FROM policy_audit_log WHERE id = $1",
            seeded["audit_id"],
        )
    assert row["legal_hold_reason"] is None


async def test_can_change_legal_hold_reason_to_a_different_value(pg_pool, seeded):
    """Updating the hold reason itself (without changing other
    columns) is allowed — useful when an initial generic reason is
    later refined with the specific ticket / docket reference."""
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = 'pending' WHERE id = $1",
            seeded["audit_id"],
        )
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = $1 WHERE id = $2",
            "SEC-2026-014: see legal/preservation/2026-06-10.eml",
            seeded["audit_id"],
        )
        row = await conn.fetchrow(
            "SELECT legal_hold_reason FROM policy_audit_log WHERE id = $1",
            seeded["audit_id"],
        )
    assert row["legal_hold_reason"].startswith("SEC-2026-014")


# ── Same shape on baseline_snapshots ────────────────────────────────


async def test_baseline_legal_hold_blocks_delete(pg_pool, seeded):
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE baseline_snapshots SET legal_hold_reason = 'reason' WHERE id = $1",
            seeded["baseline_id"],
        )
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await conn.execute(
                "DELETE FROM baseline_snapshots WHERE id = $1",
                seeded["baseline_id"],
            )


async def test_baseline_legal_hold_blocks_label_update(pg_pool, seeded):
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE baseline_snapshots SET legal_hold_reason = 'reason' WHERE id = $1",
            seeded["baseline_id"],
        )
        with pytest.raises(asyncpg.exceptions.CheckViolationError):
            await conn.execute(
                "UPDATE baseline_snapshots SET label = 'tampered' WHERE id = $1",
                seeded["baseline_id"],
            )
