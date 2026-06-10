"""Migration 017 — append-only triggers on policy_audit_log and
baseline_snapshots.

These tests pin the contract: INSERT works, UPDATE and DELETE raise.
Without DB-level enforcement an attacker with write access could
silently rewrite the audit trail; this gate makes the audit log
tamper-evident at the storage layer.

The pg_pool fixture truncates after the test (not delete-row-by-row),
and TRUNCATE does NOT fire BEFORE UPDATE / BEFORE DELETE triggers, so
the tests are not coupled to the cleanup path.

If we ever legitimately need to fix bad data in either table, the
required dance is DROP TRIGGER → fix → CREATE TRIGGER, which leaves a
trail in system_audit_log for the operator who did it (the migration
preamble documents this).
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
async def seeded_for_audit(pg_pool):
    """Seed the FK-required parents for a single policy_audit_log row."""
    async with pg_pool.acquire() as conn:
        tenant_id = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Immutability Test Tenant",
        )
        user_id = await conn.fetchval(
            """INSERT INTO tenant_users
                  (tenant_id, email, role, mfa_required, password_hash)
               VALUES ($1, $2, 'account_owner', false, $3) RETURNING id""",
            tenant_id, "immut@example.com",
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
    return {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "policy_id": policy_id,
        "audit_id": audit_id,
    }


@pytest_asyncio.fixture(loop_scope="session")
async def seeded_for_baseline(pg_pool):
    """Seed a baseline_snapshots row to mutate."""
    async with pg_pool.acquire() as conn:
        tenant_id = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Baseline Immutability Tenant",
        )
        baseline_id = await conn.fetchval(
            """
            INSERT INTO baseline_snapshots
                (tenant_id, bundle_sha256, label, summary, source)
            VALUES ($1, $2, 'pre-test baseline',
                    '{"host_count": 0, "total_evaluations": 0, "passing": 0,
                      "failing": 0, "errors": 0, "by_framework": {}}'::jsonb,
                    'manual')
            RETURNING id
            """,
            tenant_id, "a" * 64,
        )
    return {"tenant_id": tenant_id, "baseline_id": baseline_id}


# ── policy_audit_log ────────────────────────────────────────────────


async def test_policy_audit_log_insert_works(pg_pool, seeded_for_audit):
    """Sanity: the trigger must NOT break the insert path."""
    async with pg_pool.acquire() as conn:
        rid = await conn.fetchval(
            """
            INSERT INTO policy_audit_log
                (tenant_id, tenant_user_id, customer_policy_id, action, details)
            VALUES ($1, $2, $3, 'rego_generated', '{"foo": "bar"}'::jsonb)
            RETURNING id
            """,
            seeded_for_audit["tenant_id"],
            seeded_for_audit["user_id"],
            seeded_for_audit["policy_id"],
        )
        assert rid is not None


async def test_policy_audit_log_update_is_blocked(pg_pool, seeded_for_audit):
    """The trigger fires before the column write, so any UPDATE raises."""
    async with pg_pool.acquire() as conn:
        with pytest.raises(asyncpg.exceptions.CheckViolationError) as exc:
            await conn.execute(
                "UPDATE policy_audit_log SET action = 'tampered' WHERE id = $1",
                seeded_for_audit["audit_id"],
            )
    # The trigger's RAISE EXCEPTION names the table + operation; the
    # exact wording is part of the operator-facing contract.
    msg = str(exc.value)
    assert "policy_audit_log" in msg
    assert "UPDATE" in msg
    assert "append-only" in msg.lower()


async def test_policy_audit_log_delete_is_blocked(pg_pool, seeded_for_audit):
    async with pg_pool.acquire() as conn:
        with pytest.raises(asyncpg.exceptions.CheckViolationError) as exc:
            await conn.execute(
                "DELETE FROM policy_audit_log WHERE id = $1",
                seeded_for_audit["audit_id"],
            )
    msg = str(exc.value)
    assert "policy_audit_log" in msg
    assert "DELETE" in msg


# ── baseline_snapshots ──────────────────────────────────────────────


async def test_baseline_snapshots_insert_works(pg_pool, seeded_for_baseline):
    """Sanity: the trigger must NOT break the insert path."""
    async with pg_pool.acquire() as conn:
        rid = await conn.fetchval(
            """
            INSERT INTO baseline_snapshots
                (tenant_id, bundle_sha256, label, summary, source)
            VALUES ($1, $2, 'second baseline',
                    '{"host_count": 0, "total_evaluations": 0, "passing": 0,
                      "failing": 0, "errors": 0, "by_framework": {}}'::jsonb,
                    'manual')
            RETURNING id
            """,
            seeded_for_baseline["tenant_id"],
            "b" * 64,
        )
        assert rid is not None


async def test_baseline_snapshots_update_is_blocked(pg_pool, seeded_for_baseline):
    async with pg_pool.acquire() as conn:
        with pytest.raises(asyncpg.exceptions.CheckViolationError) as exc:
            await conn.execute(
                "UPDATE baseline_snapshots SET label = 'tampered' WHERE id = $1",
                seeded_for_baseline["baseline_id"],
            )
    msg = str(exc.value)
    assert "baseline_snapshots" in msg
    assert "UPDATE" in msg


async def test_baseline_snapshots_delete_is_blocked(pg_pool, seeded_for_baseline):
    async with pg_pool.acquire() as conn:
        with pytest.raises(asyncpg.exceptions.CheckViolationError) as exc:
            await conn.execute(
                "DELETE FROM baseline_snapshots WHERE id = $1",
                seeded_for_baseline["baseline_id"],
            )
    msg = str(exc.value)
    assert "baseline_snapshots" in msg
    assert "DELETE" in msg


# ── Recovery path ───────────────────────────────────────────────────


async def test_drop_trigger_then_update_works(pg_pool, seeded_for_audit):
    """The documented recovery path: DROP the trigger, fix bad data,
    re-CREATE the trigger. This test pins that the DROP / CREATE
    cycle actually unblocks mutations — without it, the "fix bad
    data" runbook would be a lie.

    We wrap the DROP + UPDATE + restoration in a single transaction
    so that if pytest is killed mid-test (SIGKILL, fixture teardown
    explosion) the trigger pop is rolled back and the next test sees
    an immutable table. PostgreSQL is happy to DROP a trigger inside
    a transaction; commit happens at the end."""
    async with pg_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "DROP TRIGGER trg_policy_audit_log_no_update ON policy_audit_log"
            )
            await conn.execute(
                "UPDATE policy_audit_log SET action = 'recovery_test' WHERE id = $1",
                seeded_for_audit["audit_id"],
            )
            row = await conn.fetchrow(
                "SELECT action FROM policy_audit_log WHERE id = $1",
                seeded_for_audit["audit_id"],
            )
            assert row["action"] == "recovery_test"
            await conn.execute(
                """
                CREATE TRIGGER trg_policy_audit_log_no_update
                    BEFORE UPDATE ON policy_audit_log
                    FOR EACH ROW EXECUTE FUNCTION
                        enforce_policy_audit_log_append_only()
                """,
            )


# ── FK cascade exception ────────────────────────────────────────────


async def test_fk_set_null_cascade_is_allowed(pg_pool, seeded_for_audit):
    """The trigger lets the ON DELETE SET NULL cascade fire — without
    this, hard-deleting a tenant_user with audit history would fail
    and the UI's "(user removed)" affordance would silently break."""
    async with pg_pool.acquire() as conn:
        # Deleting the user should cascade to UPDATE the audit row's
        # tenant_user_id to NULL.
        await conn.execute(
            "DELETE FROM tenant_users WHERE id = $1",
            seeded_for_audit["user_id"],
        )
        row = await conn.fetchrow(
            "SELECT tenant_user_id, action FROM policy_audit_log WHERE id = $1",
            seeded_for_audit["audit_id"],
        )
        assert row["tenant_user_id"] is None
        # Other columns must be untouched — the trigger should refuse
        # any concurrent mutation outside the FK-NULL window.
        assert row["action"] == "uploaded"


async def test_direct_user_change_still_blocked(pg_pool, seeded_for_audit):
    """The FK-NULL allowance is narrow: a direct UPDATE that sets
    tenant_user_id to a DIFFERENT non-NULL value (impersonation
    attempt) must still be rejected, even though tenant_user_id is
    technically one of the allowed-to-mutate columns."""
    async with pg_pool.acquire() as conn:
        other_user = await conn.fetchval(
            """INSERT INTO tenant_users
                  (tenant_id, email, role, mfa_required, password_hash)
               VALUES ($1, $2, 'editor', false, $3) RETURNING id""",
            seeded_for_audit["tenant_id"], "other@example.com",
            bcrypt.hashpw(b"x" * 24, bcrypt.gensalt(rounds=4)).decode(),
        )
        with pytest.raises(asyncpg.exceptions.CheckViolationError) as exc:
            await conn.execute(
                "UPDATE policy_audit_log SET tenant_user_id = $1 WHERE id = $2",
                other_user, seeded_for_audit["audit_id"],
            )
    assert "append-only" in str(exc.value).lower()
