"""Integration tests for GET /portal/v1/me/policies/{id}/audit-log (PR 21).

Exercises:
  - 404 on non-existent or foreign-tenant policy (no existence leak)
  - actor_email join (and the NULL fallback when the user is deleted)
  - reverse-chronological order
  - cursor pagination by `before_id` (no overlap, no gap)
  - the limit cap (server enforces 1-200)

`require_tenant_user_mfa` is dependency-overridden so the tests can
seed a synthetic session pointing at the right tenant + user — same
pattern the existing admin-router tests use against the DB pool.
"""
from __future__ import annotations

from uuid import UUID

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


# ── Test scaffolding ──────────────────────────────────────────────────


@pytest_asyncio.fixture(loop_scope="session")
async def seeded(pg_pool):
    """Seed two tenants (A, B), each with a user and a policy.

    Returns the IDs we need to assert against. Direct INSERTs bypass
    the HTTP routes so audit-log tests don't depend on the publish /
    review flows being correct — each test fails in exactly one place.
    """
    async with pg_pool.acquire() as conn:
        ta = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1,'active') RETURNING id",
            "Tenant A",
        )
        tb = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1,'active') RETURNING id",
            "Tenant B",
        )
        ua = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'editor', false) RETURNING id""",
            ta,
            "alice@a.example",
        )
        ub = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'editor', false) RETURNING id""",
            tb,
            "bob@b.example",
        )
        pa = await conn.fetchval(
            """INSERT INTO customer_policies
                   (tenant_id, name, framework_bucket, policy_source,
                    version_semver, status)
               VALUES ($1,'Policy A','iso27001','prose_upload','v1.0.0','draft')
               RETURNING id""",
            ta,
        )
        pb = await conn.fetchval(
            """INSERT INTO customer_policies
                   (tenant_id, name, framework_bucket, policy_source,
                    version_semver, status)
               VALUES ($1,'Policy B','iso27001','prose_upload','v1.0.0','draft')
               RETURNING id""",
            tb,
        )
    return {
        "tenant_a": ta,
        "tenant_b": tb,
        "user_a": ua,
        "user_b": ub,
        "policy_a": pa,
        "policy_b": pb,
    }


@pytest_asyncio.fixture(loop_scope="session")
async def client_for(pg_pool):
    """Returns a factory: given a (tenant_id, user_id), yields an
    AsyncClient whose require_tenant_user_mfa is overridden to look
    like that user. Reuses the same pool for query + dependency."""
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.core.sessions import require_tenant_user, require_tenant_user_mfa

    async def _get_pool():
        return pg_pool

    def _make(tenant_id: UUID, user_id: UUID):
        async def _fake_user():
            return {
                "tenant_id": tenant_id,
                "tenant_user_id": user_id,
                "role": "editor",
                "mfa_required": False,
                "mfa_verified": True,
            }

        app.dependency_overrides[get_portal_pool] = _get_pool
        app.dependency_overrides[require_tenant_user] = _fake_user
        app.dependency_overrides[require_tenant_user_mfa] = _fake_user
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test")

    yield _make
    app.dependency_overrides.clear()


async def _insert_audit(pool, tenant_id, user_id, policy_id, action, details=None):
    """Helper for seeding policy_audit_log rows. Returns the id."""
    import json
    return await pool.fetchval(
        """INSERT INTO policy_audit_log
               (tenant_id, tenant_user_id, customer_policy_id, action, details)
           VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING id""",
        tenant_id,
        user_id,
        policy_id,
        action,
        json.dumps(details or {}),
    )


# ── Tests ─────────────────────────────────────────────────────────────


async def test_returns_actions_in_reverse_chronological_order(
    pg_pool, seeded, client_for
):
    """Newest action first; `at` order matches `id DESC` because both
    advance monotonically per insert."""
    for action in ("policy_uploaded", "ir_extracted", "rego_generated", "published"):
        await _insert_audit(
            pg_pool, seeded["tenant_a"], seeded["user_a"], seeded["policy_a"], action
        )

    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(f"/api/portal/v1/me/policies/{seeded['policy_a']}/audit-log")
    assert r.status_code == 200
    rows = r.json()
    assert [r["action"] for r in rows] == [
        "published",
        "rego_generated",
        "ir_extracted",
        "policy_uploaded",
    ]


async def test_actor_email_is_joined_when_user_exists(
    pg_pool, seeded, client_for
):
    await _insert_audit(
        pg_pool, seeded["tenant_a"], seeded["user_a"], seeded["policy_a"], "published"
    )
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(f"/api/portal/v1/me/policies/{seeded['policy_a']}/audit-log")
    assert r.json()[0]["actor_email"] == "alice@a.example"


async def test_actor_email_is_null_when_user_deleted(
    pg_pool, seeded, client_for
):
    """tenant_user_id has FK ON DELETE SET NULL; the audit entry
    survives, but the actor_email join returns NULL. UI renders
    that as '(user removed)'."""
    await _insert_audit(
        pg_pool, seeded["tenant_a"], seeded["user_a"], seeded["policy_a"], "published"
    )
    async with pg_pool.acquire() as conn:
        await conn.execute("DELETE FROM tenant_users WHERE id = $1", seeded["user_a"])

    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(f"/api/portal/v1/me/policies/{seeded['policy_a']}/audit-log")
    assert r.status_code == 200
    [row] = r.json()
    assert row["actor_email"] is None
    assert row["tenant_user_id"] is None


async def test_404_on_foreign_tenant_policy(seeded, client_for):
    """Asking about another tenant's policy 404s identically to a
    non-existent policy id — no existence leak across tenants."""
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(f"/api/portal/v1/me/policies/{seeded['policy_b']}/audit-log")
    assert r.status_code == 404


async def test_404_on_nonexistent_policy(seeded, client_for):
    bogus = "11111111-2222-3333-4444-555555555555"
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(f"/api/portal/v1/me/policies/{bogus}/audit-log")
    assert r.status_code == 404


async def test_cursor_pagination_is_complete_and_non_overlapping(
    pg_pool, seeded, client_for
):
    """Two pages of an audit log should partition it exactly: no row
    missing, no row duplicated. Cursor is bigserial id (unique).
    """
    ids: list[int] = []
    for action in (
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
    ):
        ids.append(
            await _insert_audit(
                pg_pool, seeded["tenant_a"], seeded["user_a"], seeded["policy_a"], action
            )
        )

    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r1 = await c.get(
            f"/api/portal/v1/me/policies/{seeded['policy_a']}/audit-log?limit=4"
        )
        assert r1.status_code == 200
        page1 = r1.json()
        assert len(page1) == 4

        last_id = page1[-1]["id"]
        r2 = await c.get(
            f"/api/portal/v1/me/policies/{seeded['policy_a']}/audit-log"
            f"?limit=4&before_id={last_id}"
        )
        assert r2.status_code == 200
        page2 = r2.json()
        assert len(page2) == 4
        # No overlap and ordering is preserved.
        assert {row["id"] for row in page1} & {row["id"] for row in page2} == set()
        assert page2[0]["id"] < page1[-1]["id"]


async def test_limit_clamps_at_400(seeded, client_for):
    """limit=300 (over the 200 cap) → 422."""
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(
            f"/api/portal/v1/me/policies/{seeded['policy_a']}/audit-log?limit=300"
        )
    assert r.status_code == 422
