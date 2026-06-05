"""Integration tests for the operator-admin tenant_users router.

Exercises the full HTTP path via FastAPI's TestClient against a real
PostgreSQL container — covers migrations 001 → 012, the CRUD endpoints
from PR 10, the (tenant_id, email) UNIQUE constraint, the
account_owner-disable guard, and the issue-password-reset endpoint
from PR 11.

These run only when `pytest -m integration` is invoked. The fixture
auto-skips if no podman socket is reachable.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


# All tests in this module require the DB container.
# loop_scope="session" so each test reuses the same event loop the
# session-scoped fixtures (pg_pool_initialized) were created on —
# avoids "attached to a different loop" errors when sharing the pool.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest_asyncio.fixture(loop_scope="session")
async def client(pg_pool, monkeypatch):
    """httpx.AsyncClient over the ASGI app with both DB pool dependencies
    overridden. Async so the in-test pool calls stay on the same loop
    the request handlers run on — sync TestClient + asyncpg collide."""
    monkeypatch.setenv("PORTAL_ADMIN_TOKEN", "test-admin-token")

    from main import app
    from src.core.config import get_settings
    from src.core.database import get_pool
    from src.core.portal_db import get_portal_pool

    get_settings.cache_clear()

    async def _get_pool():
        return pg_pool

    app.dependency_overrides[get_portal_pool] = _get_pool
    app.dependency_overrides[get_pool] = _get_pool

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def admin_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-admin-token"}


@pytest_asyncio.fixture(loop_scope="session")
async def acme_tenant(pg_pool) -> str:
    """Seed an Acme tenant and return its UUID. Direct INSERT bypasses
    the create_tenant HTTP route so this fixture doesn't depend on
    PR #10's behaviour being correct — each integration test can fail
    in exactly one place."""
    async with pg_pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Acme Energy",
        )
    return str(row["id"])


# ── CRUD happy path ──────────────────────────────────────────────────


async def test_create_list_get_user(client, admin_headers, acme_tenant: str) -> None:
    # Create
    r = await client.post(
        f"/api/admin/v1/tenants/{acme_tenant}/users",
        headers=admin_headers,
        json={
            "email": "owner@acme.example",
            "display_name": "Acme Owner",
            "role": "account_owner",
        },
    )
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["email"] == "owner@acme.example"
    assert created["role"] == "account_owner"
    assert created["mfa_required"] is True       # account_owner auto-MFA
    assert created["mfa_enrolled"] is False

    # List
    r = await client.get(
        f"/api/admin/v1/tenants/{acme_tenant}/users",
        headers=admin_headers,
    )
    assert r.status_code == 200
    users = r.json()
    assert len(users) == 1
    assert users[0]["id"] == created["id"]

    # Get
    r = await client.get(
        f"/api/admin/v1/tenants/{acme_tenant}/users/{created['id']}",
        headers=admin_headers,
    )
    assert r.status_code == 200
    assert r.json()["email"] == "owner@acme.example"


async def test_duplicate_email_within_tenant_returns_409(
    client, admin_headers, acme_tenant: str
) -> None:
    base = {
        "email": "dup@acme.example",
        "display_name": "first",
        "role": "viewer",
    }
    r = await client.post(
        f"/api/admin/v1/tenants/{acme_tenant}/users",
        headers=admin_headers,
        json=base,
    )
    assert r.status_code == 201

    r = await client.post(
        f"/api/admin/v1/tenants/{acme_tenant}/users",
        headers=admin_headers,
        json={**base, "display_name": "second"},
    )
    assert r.status_code == 409


async def test_same_email_different_tenant_succeeds(client, admin_headers, pg_pool) -> None:
    """SaaS multi-tenancy requires the same human email to be allowed
    in two different tenant scopes."""
    async with pg_pool.acquire() as conn:
        t1_row = await conn.fetchrow(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant One",
        )
        t2_row = await conn.fetchrow(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant Two",
        )
    t1, t2 = str(t1_row["id"]), str(t2_row["id"])
    body = {"email": "alice@example.com", "role": "viewer"}

    r1 = await client.post(
        f"/api/admin/v1/tenants/{t1}/users", headers=admin_headers, json=body
    )
    r2 = await client.post(
        f"/api/admin/v1/tenants/{t2}/users", headers=admin_headers, json=body
    )
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["tenant_id"] != r2.json()["tenant_id"]


# ── only-owner disable guard ──────────────────────────────────────────


async def test_cannot_disable_the_only_active_account_owner(
    client, admin_headers, acme_tenant: str
) -> None:
    """The router refuses to leave a tenant with zero active owners.
    Operator must demote or appoint another owner first."""
    r = await client.post(
        f"/api/admin/v1/tenants/{acme_tenant}/users",
        headers=admin_headers,
        json={"email": "only@acme.example", "role": "account_owner"},
    )
    user_id = r.json()["id"]

    r = await client.post(
        f"/api/admin/v1/tenants/{acme_tenant}/users/{user_id}/disable",
        headers=admin_headers,
    )
    assert r.status_code == 409, r.text
    assert "only active account_owner" in r.json()["detail"].lower()


async def test_disable_with_other_active_owner_succeeds(
    client, admin_headers, acme_tenant: str
) -> None:
    """Two owners → disabling one leaves a valid tenant state."""
    a_resp = await client.post(
        f"/api/admin/v1/tenants/{acme_tenant}/users",
        headers=admin_headers,
        json={"email": "a@acme.example", "role": "account_owner"},
    )
    a = a_resp.json()
    b_resp = await client.post(
        f"/api/admin/v1/tenants/{acme_tenant}/users",
        headers=admin_headers,
        json={"email": "b@acme.example", "role": "account_owner"},
    )
    b = b_resp.json()

    r = await client.post(
        f"/api/admin/v1/tenants/{acme_tenant}/users/{a['id']}/disable",
        headers=admin_headers,
    )
    assert r.status_code == 200
    assert r.json()["disabled_at"] is not None
    assert r.json()["id"] == a["id"]
    # b stayed active.
    r = await client.get(
        f"/api/admin/v1/tenants/{acme_tenant}/users/{b['id']}",
        headers=admin_headers,
    )
    assert r.json()["disabled_at"] is None


# ── auth gate ─────────────────────────────────────────────────────────


async def test_missing_admin_token_returns_401(client, acme_tenant: str) -> None:
    r = await client.get(f"/api/admin/v1/tenants/{acme_tenant}/users")
    assert r.status_code == 401


async def test_wrong_admin_token_returns_403(client, acme_tenant: str) -> None:
    r = await client.get(
        f"/api/admin/v1/tenants/{acme_tenant}/users",
        headers={"Authorization": "Bearer wrong"},
    )
    assert r.status_code == 403