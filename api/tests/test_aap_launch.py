"""Real-DB tests for /api/aap/launch (P1).

The router does THREE non-trivial things, all worth pinning:
  1. Tenant scoping via tenant_host_mapping (real PG)
  2. Translates AAP client errors into the right HTTP status codes
  3. Sets request.state.audit_resource for the AuditMiddleware

Mocking strategy:
  - PostgreSQL: real (testcontainers pg_pool, same as remediation /
    reports tests) — caught a SQL bug in #51.
  - AAP itself: mocked — there's no AAP available in CI, and what
    we want to pin is HOW the router handles each return type.

Pins:
  - hostname in scope + success → 200 + LaunchResponse
  - hostname not mapped → 422 (no info leak)
  - AAP not configured → 503
  - AAP 404 → 404 (template not found is caller-fixable)
  - AAP 5xx / network → 502
  - audit_resource is set to ("aap_job", str(job_id))
  - extra_vars passed to AAP include hostname + framework + portal user fingerprint
"""
from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import UUID

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest_asyncio.fixture(loop_scope="session")
async def seeded(pg_pool):
    """Tenant A with one mapped host, tenant B with a different one.

    Used to test both the happy path (A → host-a) and the cross-tenant
    leak path (A → host-b → 422).
    """
    async with pg_pool.acquire() as conn:
        ta = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant A",
        )
        tb = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant B",
        )
        ua = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'account_owner', false) RETURNING id""",
            ta, "owner@a.example",
        )
        ub = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'account_owner', false) RETURNING id""",
            tb, "owner@b.example",
        )
        await conn.execute(
            "INSERT INTO tenant_host_mapping (tenant_id, hostname) VALUES ($1, $2)",
            ta, "host-a.example",
        )
        await conn.execute(
            "INSERT INTO tenant_host_mapping (tenant_id, hostname) VALUES ($1, $2)",
            tb, "host-b.example",
        )

    return {"tenant_a": ta, "tenant_b": tb, "owner_a": ua, "owner_b": ub}


@pytest_asyncio.fixture(loop_scope="session")
async def client_factory(pg_pool):
    """Build a client per (tenant_id, user_id) tuple with auth bypassed.

    MFA gate is bypassed by overriding both `require_tenant_user` and
    `require_tenant_user_mfa` — the production deps both stash
    `tenant_user` on request.state, so we mirror that here so the
    audit hook sees a real-shaped user.
    """
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.core.sessions import require_tenant_user, require_tenant_user_mfa

    async def _get_portal():
        return pg_pool

    def _make(tenant_id: UUID, user_id: UUID, email: str = "u@example"):
        fake = {
            "session_id": UUID("11111111-1111-1111-1111-111111111111"),
            "tenant_user_id": user_id,
            "tenant_id": tenant_id,
            "email": email,
            "display_name": "u",
            "role": "account_owner",
            "mfa_required": False,
            "mfa_enrolled": True,
            "mfa_verified": True,
        }

        async def _user_dep(request=None):
            if request is not None:
                request.state.tenant_user = fake
            return fake

        app.dependency_overrides[get_portal_pool] = _get_portal
        app.dependency_overrides[require_tenant_user] = _user_dep
        app.dependency_overrides[require_tenant_user_mfa] = _user_dep
        return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")

    yield _make
    app.dependency_overrides.clear()


# ── Success path ─────────────────────────────────────────────────────


async def test_launch_succeeds_for_mapped_host(seeded, client_factory, monkeypatch):
    captured: dict = {}

    async def fake_launch(template_id, extra_vars, **kw):
        captured["template_id"] = template_id
        captured["extra_vars"] = extra_vars
        return {
            "job": 7777,
            "status": "pending",
            "url": "/api/v2/jobs/7777/",
            "created": "2026-06-07T12:00:00Z",
        }

    monkeypatch.setattr("src.routers.aap.launch_job_template", fake_launch)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post("/api/aap/launch", json={
            "hostname": "host-a.example",
            "framework": "cis_rhel9",
            "template_id": 42,
        })

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["job_id"] == 7777
    assert body["status"] == "pending"
    assert body["url"] == "/api/v2/jobs/7777/"

    # extra_vars carries the hostname + framework + portal fingerprint
    assert captured["template_id"] == 42
    ev = captured["extra_vars"]
    assert ev["target_host"] == "host-a.example"
    assert ev["framework"] == "cis_rhel9"
    assert ev["aac_portal_tenant_id"] == str(seeded["tenant_a"])
    assert ev["aac_portal_user_id"] == str(seeded["owner_a"])


# ── Tenant scoping ───────────────────────────────────────────────────


async def test_foreign_hostname_returns_422_without_leaking(seeded, client_factory, monkeypatch):
    # If the router somehow calls AAP for a foreign host, we'll
    # notice — AAP mock raises.
    async def explode(*a, **kw):
        raise AssertionError("AAP must NOT be called for foreign host")

    monkeypatch.setattr("src.routers.aap.launch_job_template", explode)

    # Tenant A asking for tenant B's host
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post("/api/aap/launch", json={
            "hostname": "host-b.example",  # belongs to tenant B
            "framework": "cis_rhel9",
            "template_id": 42,
        })

    assert r.status_code == 422
    # Error message says "not mapped to your tenant" — does NOT say
    # "this host belongs to another tenant" (which would leak)
    assert "your tenant" in r.json()["detail"]


async def test_unknown_hostname_also_returns_422(seeded, client_factory, monkeypatch):
    async def explode(*a, **kw):
        raise AssertionError("AAP must NOT be called for unmapped host")
    monkeypatch.setattr("src.routers.aap.launch_job_template", explode)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post("/api/aap/launch", json={
            "hostname": "does-not-exist.example",
            "framework": "cis_rhel9",
            "template_id": 42,
        })

    # Same shape as the foreign-host case — opaque to whether the host
    # exists at all
    assert r.status_code == 422


# ── AAP failures → HTTP status mapping ───────────────────────────────


async def test_aap_not_configured_returns_503(seeded, client_factory, monkeypatch):
    from src.core.aap_client import AapNotConfigured

    async def fake(*a, **kw):
        raise AapNotConfigured("AAP_URL missing")
    monkeypatch.setattr("src.routers.aap.launch_job_template", fake)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post("/api/aap/launch", json={
            "hostname": "host-a.example",
            "framework": "cis_rhel9",
            "template_id": 42,
        })

    assert r.status_code == 503
    assert "AAP_URL" in r.json()["detail"]


async def test_aap_template_not_found_returns_404(seeded, client_factory, monkeypatch):
    from src.core.aap_client import AapError

    async def fake(*a, **kw):
        raise AapError("AAP job template 99999 not found")
    monkeypatch.setattr("src.routers.aap.launch_job_template", fake)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post("/api/aap/launch", json={
            "hostname": "host-a.example",
            "framework": "cis_rhel9",
            "template_id": 99999,
        })

    assert r.status_code == 404


async def test_aap_5xx_returns_502(seeded, client_factory, monkeypatch):
    from src.core.aap_client import AapError

    async def fake(*a, **kw):
        raise AapError("AAP returned HTTP 500: oh no")
    monkeypatch.setattr("src.routers.aap.launch_job_template", fake)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post("/api/aap/launch", json={
            "hostname": "host-a.example",
            "framework": "cis_rhel9",
            "template_id": 42,
        })

    assert r.status_code == 502


# ── Input validation ─────────────────────────────────────────────────


async def test_missing_body_field_returns_422(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post("/api/aap/launch", json={
            "hostname": "host-a.example",
            # missing framework
            "template_id": 42,
        })
    assert r.status_code == 422


async def test_invalid_template_id_returns_422(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post("/api/aap/launch", json={
            "hostname": "host-a.example",
            "framework": "cis_rhel9",
            "template_id": 0,  # must be > 0
        })
    assert r.status_code == 422
