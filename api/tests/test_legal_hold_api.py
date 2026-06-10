"""Admin API tests for `/api/admin/v1/legal-holds`.

Mechanism (DB-level immutability triggers + the column) is covered
by tests/test_legal_hold_triggers.py. This file is about the typed
operator surface: auth gating, conflict semantics, ID-type
validation, and the audit-trail wiring.
"""
from __future__ import annotations

import bcrypt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


ADMIN = {"Authorization": "Bearer test-admin-token"}


@pytest_asyncio.fixture(loop_scope="session")
async def seeded(pg_pool):
    """A tenant + user + policy + one audit row + one baseline."""
    async with pg_pool.acquire() as conn:
        tenant_id = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Legal Hold API Tenant",
        )
        user_id = await conn.fetchval(
            """INSERT INTO tenant_users
                  (tenant_id, email, role, mfa_required, password_hash)
               VALUES ($1, $2, 'account_owner', false, $3) RETURNING id""",
            tenant_id, "lh-api@example.com",
            bcrypt.hashpw(b"x" * 24, bcrypt.gensalt(rounds=4)).decode(),
        )
        policy_id = await conn.fetchval(
            """
            INSERT INTO customer_policies
                (tenant_id, name, framework_bucket, policy_source, status,
                 ir_json, version_semver)
            VALUES ($1, 'API Test policy', 'iso27001', 'prose_upload',
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
            VALUES ($1, $2, 'api-test', '{"host_count": 0, "total_evaluations": 0,
                    "passing": 0, "failing": 0, "errors": 0, "by_framework": {}}'::jsonb,
                    'manual')
            RETURNING id
            """,
            tenant_id, "c" * 64,
        )
    return {
        "tenant_id": str(tenant_id),
        "audit_id": int(audit_id),
        "baseline_id": str(baseline_id),
    }


@pytest_asyncio.fixture(loop_scope="session")
async def client(pg_pool):
    from main import app
    from src.core.portal_db import get_portal_pool

    async def _get_pool():
        return pg_pool

    app.dependency_overrides[get_portal_pool] = _get_pool
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.clear()


# ── Auth ─────────────────────────────────────────────────────────────


async def test_apply_requires_admin_token(client, seeded):
    r = await client.post(
        "/api/admin/v1/legal-holds",
        json={
            "resource_type": "policy_audit_log",
            "resource_id": str(seeded["audit_id"]),
            "reason": "test reason",
            "approval_ticket": "TKT-1",
        },
    )
    assert r.status_code == 401, r.text


async def test_list_requires_admin_token(client):
    r = await client.get("/api/admin/v1/legal-holds")
    assert r.status_code == 401, r.text


# ── Apply happy path ─────────────────────────────────────────────────


async def test_apply_to_policy_audit_log(client, seeded):
    r = await client.post(
        "/api/admin/v1/legal-holds",
        headers=ADMIN,
        json={
            "resource_type": "policy_audit_log",
            "resource_id": str(seeded["audit_id"]),
            "reason": "SEC-2026-014 preservation order",
            "approval_ticket": "INTERNAL-LEGAL-9182",
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["resource_type"] == "policy_audit_log"
    assert body["resource_id"] == str(seeded["audit_id"])
    assert body["reason"] == "SEC-2026-014 preservation order"
    assert body["tenant_id"] == seeded["tenant_id"]


async def test_apply_to_baseline_snapshots(client, seeded):
    r = await client.post(
        "/api/admin/v1/legal-holds",
        headers=ADMIN,
        json={
            "resource_type": "baseline_snapshots",
            "resource_id": seeded["baseline_id"],
            "reason": "Q4 2026 audit window — preserve",
            "approval_ticket": "AUDIT-2026-Q4",
        },
    )
    assert r.status_code == 201, r.text


# ── Apply error paths ────────────────────────────────────────────────


async def test_apply_404_when_row_missing(client, seeded):
    r = await client.post(
        "/api/admin/v1/legal-holds",
        headers=ADMIN,
        json={
            "resource_type": "policy_audit_log",
            "resource_id": "9999999",
            "reason": "should not apply",
            "approval_ticket": "TKT-2",
        },
    )
    assert r.status_code == 404, r.text


async def test_apply_400_when_id_type_wrong(client, seeded):
    """`policy_audit_log.id` is bigint; passing a UUID should 400."""
    r = await client.post(
        "/api/admin/v1/legal-holds",
        headers=ADMIN,
        json={
            "resource_type": "policy_audit_log",
            "resource_id": "00000000-0000-0000-0000-000000000000",
            "reason": "wrong id type",
            "approval_ticket": "TKT-3",
        },
    )
    assert r.status_code == 400, r.text
    assert "integer" in r.json()["detail"]


async def test_apply_400_when_baseline_id_not_uuid(client, seeded):
    r = await client.post(
        "/api/admin/v1/legal-holds",
        headers=ADMIN,
        json={
            "resource_type": "baseline_snapshots",
            "resource_id": "not-a-uuid",
            "reason": "wrong id type",
            "approval_ticket": "TKT-4",
        },
    )
    assert r.status_code == 400, r.text
    assert "UUID" in r.json()["detail"]


async def test_apply_422_on_short_reason(client, seeded):
    """Pydantic min_length=5 protects against placeholder reasons."""
    r = await client.post(
        "/api/admin/v1/legal-holds",
        headers=ADMIN,
        json={
            "resource_type": "policy_audit_log",
            "resource_id": str(seeded["audit_id"]),
            "reason": "x",
            "approval_ticket": "TKT-5",
        },
    )
    assert r.status_code == 422, r.text


async def test_apply_409_on_double_apply(pg_pool, client, seeded):
    """An already-held row 409s. Operator must DELETE + POST to change
    the reason — that way both intentions land in the audit log."""
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = 'existing' WHERE id = $1",
            seeded["audit_id"],
        )
    r = await client.post(
        "/api/admin/v1/legal-holds",
        headers=ADMIN,
        json={
            "resource_type": "policy_audit_log",
            "resource_id": str(seeded["audit_id"]),
            "reason": "second apply attempt",
            "approval_ticket": "TKT-6",
        },
    )
    assert r.status_code == 409, r.text
    assert "release" in r.json()["detail"].lower()


# ── Release ──────────────────────────────────────────────────────────


async def test_release_happy_path(pg_pool, client, seeded):
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = 'to release' WHERE id = $1",
            seeded["audit_id"],
        )
    r = await client.request(
        "DELETE",
        f"/api/admin/v1/legal-holds/policy_audit_log/{seeded['audit_id']}",
        headers=ADMIN,
        json={"release_ticket": "TKT-CLOSURE-7"},
    )
    assert r.status_code == 204, r.text
    async with pg_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT legal_hold_reason FROM policy_audit_log WHERE id = $1",
            seeded["audit_id"],
        )
    assert row["legal_hold_reason"] is None


async def test_release_409_when_not_held(client, seeded):
    """Releasing something that wasn't held is almost always an
    operator error (wrong row id). 409 rather than silent no-op so
    the mistake surfaces."""
    r = await client.request(
        "DELETE",
        f"/api/admin/v1/legal-holds/policy_audit_log/{seeded['audit_id']}",
        headers=ADMIN,
        json={"release_ticket": "TKT-8"},
    )
    assert r.status_code == 409, r.text


async def test_release_404_when_row_missing(client, seeded):
    r = await client.request(
        "DELETE",
        "/api/admin/v1/legal-holds/policy_audit_log/9999999",
        headers=ADMIN,
        json={"release_ticket": "TKT-9"},
    )
    assert r.status_code == 404, r.text


async def test_release_422_on_missing_ticket(client, seeded):
    r = await client.request(
        "DELETE",
        f"/api/admin/v1/legal-holds/policy_audit_log/{seeded['audit_id']}",
        headers=ADMIN,
        json={},
    )
    assert r.status_code == 422, r.text


# ── List ─────────────────────────────────────────────────────────────


async def test_list_returns_held_rows_across_both_tables(
    pg_pool, client, seeded
):
    async with pg_pool.acquire() as conn:
        await conn.execute(
            "UPDATE policy_audit_log SET legal_hold_reason = 'P' WHERE id = $1",
            seeded["audit_id"],
        )
        await conn.execute(
            "UPDATE baseline_snapshots SET legal_hold_reason = 'B' WHERE id = $1",
            seeded["baseline_id"],
        )
    r = await client.get("/api/admin/v1/legal-holds", headers=ADMIN)
    assert r.status_code == 200, r.text
    entries = r.json()
    types = sorted(e["resource_type"] for e in entries)
    assert "policy_audit_log" in types
    assert "baseline_snapshots" in types
