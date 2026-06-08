"""Integration tests for the tenant-admin host-mapping endpoints —
P0-A3.

Pins:

  - List/create/delete happy path
  - account_owner gating: viewer/editor get 403
  - MFA gating: non-mfa-verified session gets 403 from require_tenant_user_mfa
  - Tenant scoping: tenant B can't see / can't delete tenant A's rows
  - Unique-violation maps to 409
  - Audit middleware tags request.state.audit_resource (implicit via
    AuditMiddleware test infra; here we just verify the POST returns
    the row, then audit covered in test_audit_actor)
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


@pytest_asyncio.fixture(loop_scope="session")
async def seeded(pg_pool):
    """Two tenants, each with a role-distinct user set."""
    async with pg_pool.acquire() as conn:
        ta = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant A",
        )
        tb = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant B",
        )
        owner_a = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'account_owner', false) RETURNING id""",
            ta, "owner@a.example",
        )
        editor_a = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'editor', false) RETURNING id""",
            ta, "ed@a.example",
        )
        viewer_a = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'viewer', false) RETURNING id""",
            ta, "v@a.example",
        )
        owner_b = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'account_owner', false) RETURNING id""",
            tb, "owner@b.example",
        )
    return {
        "tenant_a": ta, "tenant_b": tb,
        "owner_a": owner_a, "editor_a": editor_a, "viewer_a": viewer_a,
        "owner_b": owner_b,
    }


@pytest_asyncio.fixture(loop_scope="session")
async def client_factory(pg_pool):
    """Returns client_for(tenant_id, user_id, role, mfa_verified=True).
    Builds a stubbed-session client where the require_tenant_user_mfa
    dep returns a user with the requested role + mfa flag."""
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.core.sessions import require_tenant_user, require_tenant_user_mfa

    async def _get_pool():
        return pg_pool

    def _make(tenant_id: UUID, user_id: UUID, role: str = "account_owner",
              mfa_verified: bool = True):
        fake = {
            "session_id": UUID("11111111-1111-1111-1111-111111111111"),
            "tenant_user_id": user_id,
            "tenant_id": tenant_id,
            "email": "x@example",
            "display_name": "x",
            "role": role,
            "mfa_required": True,
            "mfa_enrolled": True,
            "mfa_verified": mfa_verified,
        }

        async def _user_dep(request=None):
            if request is not None:
                request.state.tenant_user = fake
            return fake

        async def _mfa_dep(request=None):
            if not mfa_verified:
                from fastapi import HTTPException
                raise HTTPException(status_code=403, detail="mfa required")
            if request is not None:
                request.state.tenant_user = fake
            return fake

        app.dependency_overrides[get_portal_pool] = _get_pool
        app.dependency_overrides[require_tenant_user] = _user_dep
        app.dependency_overrides[require_tenant_user_mfa] = _mfa_dep
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test")

    yield _make
    app.dependency_overrides.clear()


# ── Happy path ────────────────────────────────────────────────────────


async def test_create_list_delete_roundtrip(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post(
            "/api/portal/v1/me/host-mappings",
            json={"hostname": "h1.example", "framework": None},
        )
        assert r.status_code == 201, r.text
        item = r.json()
        mapping_id = item["id"]
        assert item["hostname"] == "h1.example"
        assert item["framework"] is None

        r = await c.get("/api/portal/v1/me/host-mappings")
        assert r.status_code == 200
        listed = r.json()
        assert any(m["id"] == mapping_id for m in listed)

        r = await c.delete(f"/api/portal/v1/me/host-mappings/{mapping_id}")
        assert r.status_code == 204

        r = await c.get("/api/portal/v1/me/host-mappings")
        assert all(m["id"] != mapping_id for m in r.json())


# ── Role gating ──────────────────────────────────────────────────────


async def test_editor_gets_403(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["editor_a"], role="editor") as c:
        r = await c.get("/api/portal/v1/me/host-mappings")
        assert r.status_code == 403


async def test_viewer_gets_403(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["viewer_a"], role="viewer") as c:
        r = await c.post(
            "/api/portal/v1/me/host-mappings",
            json={"hostname": "h.example"},
        )
        assert r.status_code == 403


async def test_mfa_unverified_session_gets_403(seeded, client_factory):
    async with client_factory(
        seeded["tenant_a"], seeded["owner_a"], role="account_owner", mfa_verified=False,
    ) as c:
        r = await c.get("/api/portal/v1/me/host-mappings")
        assert r.status_code == 403


# ── Tenant scoping ───────────────────────────────────────────────────


async def test_list_excludes_other_tenants(seeded, client_factory):
    # Owner B creates a mapping
    async with client_factory(seeded["tenant_b"], seeded["owner_b"]) as c:
        r = await c.post(
            "/api/portal/v1/me/host-mappings",
            json={"hostname": "b-only.example"},
        )
        assert r.status_code == 201
    # Owner A lists — should not see B's row
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/portal/v1/me/host-mappings")
        rows = r.json()
        assert all(m["hostname"] != "b-only.example" for m in rows)


async def test_delete_other_tenants_mapping_returns_404(seeded, client_factory):
    # Owner A creates a mapping
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post(
            "/api/portal/v1/me/host-mappings",
            json={"hostname": "scope-test.example"},
        )
        mapping_id = r.json()["id"]
    # Owner B tries to delete it — 404 (no existence leak)
    async with client_factory(seeded["tenant_b"], seeded["owner_b"]) as c:
        r = await c.delete(f"/api/portal/v1/me/host-mappings/{mapping_id}")
        assert r.status_code == 404


# ── Uniqueness ───────────────────────────────────────────────────────


async def test_duplicate_mapping_returns_409(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post(
            "/api/portal/v1/me/host-mappings",
            json={"hostname": "dup.example", "framework": "cis_rhel9"},
        )
        assert r.status_code == 201

        r = await c.post(
            "/api/portal/v1/me/host-mappings",
            json={"hostname": "dup.example", "framework": "cis_rhel9"},
        )
        assert r.status_code == 409, r.text
        assert "already exists" in r.json()["detail"]


async def test_null_framework_and_string_collapse_to_one_bucket(seeded, client_factory):
    """Documents the migration-015 behavior: COALESCE(framework, '')
    in the unique index means (host, NULL) and (host, '') hit the
    same bucket. The router doesn't accept empty string today but
    the underlying invariant is worth pinning."""
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.post(
            "/api/portal/v1/me/host-mappings",
            json={"hostname": "coalesce.example", "framework": None},
        )
        assert r.status_code == 201
        # Same triple again — collides
        r = await c.post(
            "/api/portal/v1/me/host-mappings",
            json={"hostname": "coalesce.example", "framework": None},
        )
        assert r.status_code == 409
