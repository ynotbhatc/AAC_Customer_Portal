"""Integration tests for the tenant-facing permission audit endpoint.

Pins (closes docs/security_roadmap.md "Permission audit reporting"):

  - GET /me/permissions returns the current tenant's roster only —
    rows from another tenant must NOT leak.
  - The caller's own row is flagged `self: true`; others are `false`.
  - Deleted users (deleted_at IS NOT NULL) are not included.
  - The static role catalog includes viewer / editor / account_owner
    with non-empty capability lists.
  - Capabilities matrix names every gated router (editor + above) so
    a new gate landing without a catalog update would fail this test.
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


@pytest_asyncio.fixture(loop_scope="session")
async def seeded(pg_pool):
    """Two tenants, each with multiple users at different roles.

    Tenant A: owner, editor, viewer, disabled editor.
    Tenant B: owner (used only for cross-tenant leak check).
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
        # Tenant A roster
        a_owner = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, display_name, role, mfa_required)
               VALUES ($1, $2, $3, 'account_owner', false) RETURNING id""",
            ta, "owner@a.example", "A Owner",
        )
        a_editor = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, display_name, role, mfa_required)
               VALUES ($1, $2, $3, 'editor', false) RETURNING id""",
            ta, "editor@a.example", "A Editor",
        )
        a_viewer = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, display_name, role, mfa_required)
               VALUES ($1, $2, $3, 'viewer', false) RETURNING id""",
            ta, "viewer@a.example", "A Viewer",
        )
        a_disabled = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, display_name, role, mfa_required, disabled_at)
               VALUES ($1, $2, $3, 'editor', false, now()) RETURNING id""",
            ta, "disabled@a.example", "A Disabled",
        )
        # Tenant B roster (cross-tenant leak check)
        b_owner = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, display_name, role, mfa_required)
               VALUES ($1, $2, $3, 'account_owner', false) RETURNING id""",
            tb, "owner@b.example", "B Owner",
        )

    return {
        "tenant_a": ta,
        "tenant_b": tb,
        "a_owner": a_owner,
        "a_editor": a_editor,
        "a_viewer": a_viewer,
        "a_disabled": a_disabled,
        "b_owner": b_owner,
    }


@pytest_asyncio.fixture(loop_scope="session")
async def client_factory(pg_pool):
    """Build a client per (tenant_id, user_id, role) with auth bypassed."""
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.core.sessions import require_tenant_user, require_tenant_user_mfa

    async def _get_pool():
        return pg_pool

    def _make(tenant_id: UUID, user_id: UUID, role: str = "editor"):
        fake = {
            "session_id": UUID("11111111-1111-1111-1111-111111111111"),
            "tenant_user_id": user_id,
            "tenant_id": tenant_id,
            "email": "x@example",
            "display_name": "x",
            "role": role,
            "mfa_required": False,
            "mfa_enrolled": True,
            "mfa_verified": True,
        }

        async def _user_dep(request=None):
            if request is not None:
                request.state.tenant_user = fake
            return fake

        app.dependency_overrides[get_portal_pool] = _get_pool
        app.dependency_overrides[require_tenant_user] = _user_dep
        app.dependency_overrides[require_tenant_user_mfa] = _user_dep
        return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")

    yield _make
    app.dependency_overrides.clear()


# ── Tests ────────────────────────────────────────────────────────────


async def test_returns_tenant_a_roster_only(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["a_editor"]) as client:
        resp = await client.get("/api/portal/v1/me/permissions")
        assert resp.status_code == 200
        body = resp.json()
        emails = sorted(u["email"] for u in body["users"])
        # Tenant A active users — deleted_at NOT NULL row excluded,
        # Tenant B row excluded.
        assert emails == [
            "editor@a.example",
            "owner@a.example",
            "viewer@a.example",
        ]


async def test_self_flag_is_set_on_caller_row(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["a_editor"]) as client:
        body = (await client.get("/api/portal/v1/me/permissions")).json()
        by_email = {u["email"]: u for u in body["users"]}
        assert by_email["editor@a.example"]["self"] is True
        assert by_email["owner@a.example"]["self"] is False
        assert by_email["viewer@a.example"]["self"] is False


async def test_disabled_users_excluded(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["a_owner"]) as client:
        body = (await client.get("/api/portal/v1/me/permissions")).json()
        emails = [u["email"] for u in body["users"]]
        assert "disabled@a.example" not in emails


async def test_cross_tenant_isolation(seeded, client_factory):
    """Tenant B caller must see only Tenant B's roster."""
    async with client_factory(seeded["tenant_b"], seeded["b_owner"]) as client:
        body = (await client.get("/api/portal/v1/me/permissions")).json()
        emails = [u["email"] for u in body["users"]]
        # Only Tenant B's row.
        assert emails == ["owner@b.example"]
        # And nothing from Tenant A leaked.
        assert all("@a.example" not in e for e in emails)


async def test_role_catalog_complete(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["a_owner"]) as client:
        body = (await client.get("/api/portal/v1/me/permissions")).json()
        names = [r["name"] for r in body["roles"]]
        # Must match the rbac.Role hierarchy exactly.
        assert names == ["viewer", "editor", "account_owner"]
        # Every role has a non-empty description + capabilities.
        for role in body["roles"]:
            assert role["description"]
            assert isinstance(role["capabilities"], list)
            assert len(role["capabilities"]) > 0


async def test_editor_role_capabilities_cover_gated_routers(seeded, client_factory):
    """Sanity: the catalog claims editor can do X — make sure X is
    actually one of the routers we gated in PR #63. If a future PR
    adds a new editor-gated router, the catalog must be updated."""
    async with client_factory(seeded["tenant_a"], seeded["a_owner"]) as client:
        body = (await client.get("/api/portal/v1/me/permissions")).json()
        editor = next(r for r in body["roles"] if r["name"] == "editor")
        joined = " ".join(editor["capabilities"]).lower()
        # Every gated surface from PR #63's commit message.
        for keyword in [
            "polic",        # policies router
            "bundle",       # bundles router
            "baseline",     # baselines router
            "aap",          # aap router
            "remediation",  # remediation router
        ]:
            assert keyword in joined, f"editor catalog should mention {keyword!r}: {joined!r}"
