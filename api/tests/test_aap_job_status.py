"""Real-DB tests for GET /api/aap/jobs/{job_id} (AAP launch v2).

Tenant scoping for this endpoint is sourced from system_audit_log:
the launch endpoint (PR #57) writes (tenant_id, 'aap_job',
job_id) on every launch. The status endpoint reads that row to
decide ownership. This test suite pins that contract end-to-end.

Mocking strategy:
  - PostgreSQL: real (testcontainers pg_pool, same as #57).
  - AAP itself: mocked — there's no AAP available in CI, and what
    we want to pin is HOW the router scopes + maps statuses.

Pins:
  - Tenant launched job → 200 with curated subset
  - Different tenant launched job → 404 (no info leak)
  - No audit row at all → 404 (job never existed for caller)
  - AAP 404 (pruned by retention) → 404 with clear detail
  - AAP not configured → 503
  - AAP 5xx → 502
  - terminal flag matches { successful, failed, error, canceled }
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


# ── Scaffolding ───────────────────────────────────────────────────────


async def _seed_audit_row(conn, tenant_id, job_id: int) -> None:
    """Insert the same audit row the launch endpoint would have written.

    `system_audit_log` columns the router cares about:
      tenant_id, resource_type, resource_id
    """
    await conn.execute(
        """
        INSERT INTO system_audit_log
            (tenant_id, method, path, status_code, resource_type, resource_id)
        VALUES ($1, 'POST', '/api/aap/launch', 200, 'aap_job', $2)
        """,
        tenant_id,
        str(job_id),
    )


@pytest_asyncio.fixture(loop_scope="session")
async def seeded(pg_pool):
    """Two tenants. Tenant A 'launched' job 1001; Tenant B 'launched' 2002.

    The router doesn't care that AAP has no such job — the AAP client
    is mocked.
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
        await _seed_audit_row(conn, ta, 1001)
        await _seed_audit_row(conn, tb, 2002)

    return {"tenant_a": ta, "tenant_b": tb, "owner_a": ua, "owner_b": ub}


@pytest_asyncio.fixture(loop_scope="session")
async def client_factory(pg_pool):
    """Bypass auth — read endpoint only needs `require_tenant_user`."""
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.core.sessions import require_tenant_user

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
            "mfa_enrolled": False,
            "mfa_verified": False,
        }

        async def _user_dep(request=None):
            if request is not None:
                request.state.tenant_user = fake
            return fake

        app.dependency_overrides[get_portal_pool] = _get_portal
        app.dependency_overrides[require_tenant_user] = _user_dep
        return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")

    yield _make
    app.dependency_overrides.clear()


# ── Tenant scoping ───────────────────────────────────────────────────


async def test_owner_can_read_their_job(seeded, client_factory, monkeypatch):
    """The job ID is in tenant A's audit log → AAP is queried → 200."""
    captured: dict = {}

    async def fake_get(job_id, **kw):
        captured["job_id"] = job_id
        return {
            "id": job_id,
            "status": "running",
            "failed": False,
            "started": "2026-06-08T12:00:00Z",
            "finished": None,
            "elapsed": 12.5,
            "url": f"/api/v2/jobs/{job_id}/",
        }

    monkeypatch.setattr("src.routers.aap.get_job", fake_get)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/aap/jobs/1001")

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["job_id"] == 1001
    assert body["status"] == "running"
    assert body["terminal"] is False
    assert body["failed"] is False
    assert body["url"] == "/api/v2/jobs/1001/"
    assert captured["job_id"] == 1001


async def test_foreign_tenant_gets_404(seeded, client_factory, monkeypatch):
    """Tenant A asking for tenant B's job. AAP must NOT be queried —
    if it is, we have a tenant-isolation bug."""
    async def explode(*a, **kw):
        raise AssertionError("AAP must NOT be queried for foreign job")
    monkeypatch.setattr("src.routers.aap.get_job", explode)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/aap/jobs/2002")

    assert r.status_code == 404
    # Detail is the same as a truly-missing job — no info leak
    assert "not found" in r.json()["detail"].lower()


async def test_unknown_job_gets_404(seeded, client_factory, monkeypatch):
    """job_id with no audit row at all → 404 without ever calling AAP."""
    async def explode(*a, **kw):
        raise AssertionError("AAP must NOT be queried for unknown job")
    monkeypatch.setattr("src.routers.aap.get_job", explode)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/aap/jobs/9999")
    assert r.status_code == 404


# ── Terminal flag ────────────────────────────────────────────────────


@pytest.mark.parametrize("aap_status,expected_terminal", [
    ("pending", False),
    ("waiting", False),
    ("running", False),
    ("successful", True),
    ("failed", True),
    ("error", True),
    ("canceled", True),
])
async def test_terminal_flag_matches_aap_state(
    seeded, client_factory, monkeypatch, aap_status, expected_terminal,
):
    async def fake_get(job_id, **kw):
        return {"id": job_id, "status": aap_status, "failed": aap_status == "failed"}
    monkeypatch.setattr("src.routers.aap.get_job", fake_get)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/aap/jobs/1001")
    assert r.status_code == 200
    assert r.json()["terminal"] is expected_terminal


# ── AAP errors → HTTP status mapping ─────────────────────────────────


async def test_aap_not_configured_returns_503(seeded, client_factory, monkeypatch):
    from src.core.aap_client import AapNotConfigured

    async def fake(*a, **kw):
        raise AapNotConfigured("AAP_URL missing")
    monkeypatch.setattr("src.routers.aap.get_job", fake)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/aap/jobs/1001")
    assert r.status_code == 503


async def test_aap_pruned_job_returns_404(seeded, client_factory, monkeypatch):
    """AAP retention has pruned the job. Audit log says we launched
    it, but it's gone in AAP. Surface as 404 with a clear detail."""
    from src.core.aap_client import AapError

    async def fake(*a, **kw):
        raise AapError("AAP job 1001 not found")
    monkeypatch.setattr("src.routers.aap.get_job", fake)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/aap/jobs/1001")
    assert r.status_code == 404
    assert "pruned" in r.json()["detail"].lower() or "retention" in r.json()["detail"].lower()


async def test_aap_5xx_returns_502(seeded, client_factory, monkeypatch):
    from src.core.aap_client import AapError

    async def fake(*a, **kw):
        raise AapError("AAP returned HTTP 500: oh no")
    monkeypatch.setattr("src.routers.aap.get_job", fake)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/aap/jobs/1001")
    assert r.status_code == 502


# ── Input validation ─────────────────────────────────────────────────


async def test_negative_job_id_returns_404(seeded, client_factory, monkeypatch):
    """Defense-in-depth — FastAPI parses the int but doesn't bound it.
    A negative job_id can't exist; refuse without querying AAP."""
    async def explode(*a, **kw):
        raise AssertionError("AAP must NOT be queried for negative job_id")
    monkeypatch.setattr("src.routers.aap.get_job", explode)

    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/aap/jobs/-1")
    # FastAPI returns 422 for an invalid int (depends on path parsing);
    # in our router, valid-but-non-positive returns 404
    assert r.status_code in (404, 422)
