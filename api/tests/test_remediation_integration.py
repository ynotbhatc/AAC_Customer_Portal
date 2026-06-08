"""Integration tests for remediation router — P0-C.

Real-DB tests (testcontainers via the `pg_pool` fixture) because the
four-eyes invariant is enforced both at the router AND at the DB
CHECK constraint, and we need to verify both layers actually fire.

Pins:

  - create → assign → submit → approve full happy path
  - assign rejects cross-tenant assignee (400)
  - assign rejects when not in 'open' (409)
  - submit rejects when not in 'in_progress' (409)
  - approve rejects when not in 'pending_approval' (409)
  - **four-eyes: approve by same user as submit returns 403**
  - **four-eyes: reject by same user as submit returns 403**
  - reject returns item to 'in_progress' and clears requested_approval_*
  - list_items filters by tenant (Tenant B doesn't see Tenant A's items)
  - get_item 404 across tenants (no existence leak via id-guessing)
  - history records every transition with the correct actor
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
    """Two tenants, each with two users (the four-eyes test needs
    two users per tenant)."""
    async with pg_pool.acquire() as conn:
        ta = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant A",
        )
        tb = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant B",
        )
        ua1 = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'editor', false) RETURNING id""",
            ta, "alice@a.example",
        )
        ua2 = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'editor', false) RETURNING id""",
            ta, "amy@a.example",
        )
        ub1 = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'editor', false) RETURNING id""",
            tb, "bob@b.example",
        )
    return {
        "tenant_a": ta, "tenant_b": tb,
        "user_a1": ua1, "user_a2": ua2,
        "user_b1": ub1,
    }


@pytest_asyncio.fixture(loop_scope="session")
async def user_client_for(pg_pool):
    """Factory: client_for(tenant_id, user_id) returns an
    AsyncClient acting as that user. Bypasses real bearer auth via
    dependency_overrides — but the require_tenant_user_mfa override
    sets request.state.tenant_user, so the routes see the right user
    + the four-eyes check has actor identity to compare against."""
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.core.sessions import require_tenant_user, require_tenant_user_mfa

    async def _get_pool():
        return pg_pool

    def _make(tenant_id: UUID, user_id: UUID):
        fake_user = {
            "session_id": UUID("11111111-1111-1111-1111-111111111111"),
            "tenant_user_id": user_id,
            "tenant_id": tenant_id,
            "email": "x@example",
            "display_name": "x",
            "role": "editor",
            "mfa_required": False,
            "mfa_enrolled": False,
            "mfa_verified": True,
        }

        async def _fake_user_dep(request=None):
            if request is not None:
                request.state.tenant_user = fake_user
            return fake_user

        app.dependency_overrides[get_portal_pool] = _get_pool
        app.dependency_overrides[require_tenant_user] = _fake_user_dep
        app.dependency_overrides[require_tenant_user_mfa] = _fake_user_dep
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test")

    yield _make
    app.dependency_overrides.clear()


def _item_payload(**overrides):
    base = {
        "hostname": "h1.example",
        "framework": "cis_rhel9",
        "control_id": "CIS-1.1.1",
        "description": "ensure cramfs is disabled",
        "severity": "high",
    }
    base.update(overrides)
    return base


# ── Happy path ────────────────────────────────────────────────────────


async def test_full_lifecycle_create_assign_submit_approve(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        # 1. create
        r = await c.post("/api/remediation", json=_item_payload())
        assert r.status_code == 201, r.text
        item = r.json()
        item_id = item["id"]
        assert item["status"] == "open"

        # 2. assign to self
        r = await c.post(
            f"/api/remediation/{item_id}/assign",
            json={"assigned_to": str(seeded["user_a1"])},
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "in_progress"

        # 3. submit (user_a1 is requester)
        r = await c.post(f"/api/remediation/{item_id}/submit", json={"notes": "done"})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "pending_approval"
        assert r.json()["requested_approval_by"] == str(seeded["user_a1"])

    # 4. user_a2 (different actor) approves
    async with user_client_for(seeded["tenant_a"], seeded["user_a2"]) as c:
        r = await c.post(f"/api/remediation/{item_id}/approve", json={"notes": "looks good"})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "approved"
        assert r.json()["approved_by"] == str(seeded["user_a2"])


# ── Four-eyes invariant ──────────────────────────────────────────────


async def test_four_eyes_approval_by_requester_is_forbidden(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        r = await c.post("/api/remediation", json=_item_payload(control_id="CIS-1.2.1"))
        item_id = r.json()["id"]
        await c.post(f"/api/remediation/{item_id}/assign", json={"assigned_to": str(seeded["user_a1"])})
        await c.post(f"/api/remediation/{item_id}/submit", json={})
        # Same user trying to approve their own submission
        r = await c.post(f"/api/remediation/{item_id}/approve", json={})
        assert r.status_code == 403, r.text
        assert "four-eyes" in r.json()["detail"].lower()


async def test_four_eyes_rejection_by_requester_is_forbidden(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        r = await c.post("/api/remediation", json=_item_payload(control_id="CIS-1.3.1"))
        item_id = r.json()["id"]
        await c.post(f"/api/remediation/{item_id}/assign", json={"assigned_to": str(seeded["user_a1"])})
        await c.post(f"/api/remediation/{item_id}/submit", json={})
        r = await c.post(f"/api/remediation/{item_id}/reject", json={"notes": "no"})
        assert r.status_code == 403
        assert "four-eyes" in r.json()["detail"].lower()


# ── State-machine guards ─────────────────────────────────────────────


async def test_assign_from_non_open_returns_409(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        r = await c.post("/api/remediation", json=_item_payload(control_id="CIS-2.1.1"))
        item_id = r.json()["id"]
        await c.post(f"/api/remediation/{item_id}/assign", json={"assigned_to": str(seeded["user_a1"])})
        # Already in_progress — second assign rejected
        r = await c.post(f"/api/remediation/{item_id}/assign", json={"assigned_to": str(seeded["user_a1"])})
        assert r.status_code == 409


async def test_submit_from_non_in_progress_returns_409(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        r = await c.post("/api/remediation", json=_item_payload(control_id="CIS-2.2.1"))
        item_id = r.json()["id"]
        # status is 'open' — submit rejected
        r = await c.post(f"/api/remediation/{item_id}/submit", json={})
        assert r.status_code == 409


async def test_approve_from_non_pending_returns_409(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        r = await c.post("/api/remediation", json=_item_payload(control_id="CIS-2.3.1"))
        item_id = r.json()["id"]
        # status is 'open' — approve rejected
        r = await c.post(f"/api/remediation/{item_id}/approve", json={})
        assert r.status_code == 409


# ── Cross-tenant safety ──────────────────────────────────────────────


async def test_assign_to_cross_tenant_user_returns_400(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        r = await c.post("/api/remediation", json=_item_payload(control_id="CIS-3.1.1"))
        item_id = r.json()["id"]
        # Try to assign to a user from Tenant B
        r = await c.post(
            f"/api/remediation/{item_id}/assign",
            json={"assigned_to": str(seeded["user_b1"])},
        )
        assert r.status_code == 400
        assert "different tenant" in r.json()["detail"]


async def test_list_excludes_other_tenants(seeded, user_client_for):
    # Tenant A creates an item
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        await c.post("/api/remediation", json=_item_payload(control_id="CIS-4.1.1"))
    # Tenant B lists — should not see it
    async with user_client_for(seeded["tenant_b"], seeded["user_b1"]) as c:
        r = await c.get("/api/remediation")
        items = r.json()
        assert all(i["control_id"] != "CIS-4.1.1" for i in items), \
            f"Tenant B leaked Tenant A items: {items}"


async def test_get_item_404_across_tenants(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        r = await c.post("/api/remediation", json=_item_payload(control_id="CIS-4.2.1"))
        item_id = r.json()["id"]
    # Tenant B GETs by id — should 404 identically to "not found"
    async with user_client_for(seeded["tenant_b"], seeded["user_b1"]) as c:
        r = await c.get(f"/api/remediation/{item_id}")
        assert r.status_code == 404


# ── Reject flow ───────────────────────────────────────────────────────


async def test_reject_returns_to_in_progress_and_clears_requester(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        r = await c.post("/api/remediation", json=_item_payload(control_id="CIS-5.1.1"))
        item_id = r.json()["id"]
        await c.post(f"/api/remediation/{item_id}/assign", json={"assigned_to": str(seeded["user_a1"])})
        await c.post(f"/api/remediation/{item_id}/submit", json={})

    # user_a2 rejects
    async with user_client_for(seeded["tenant_a"], seeded["user_a2"]) as c:
        r = await c.post(f"/api/remediation/{item_id}/reject", json={"notes": "missing evidence"})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "in_progress"
        assert r.json()["requested_approval_by"] is None


# ── History ──────────────────────────────────────────────────────────


async def test_history_records_every_transition(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a1"]) as c:
        r = await c.post("/api/remediation", json=_item_payload(control_id="CIS-6.1.1"))
        item_id = r.json()["id"]
        await c.post(f"/api/remediation/{item_id}/assign", json={"assigned_to": str(seeded["user_a1"])})
        await c.post(f"/api/remediation/{item_id}/submit", json={})
    async with user_client_for(seeded["tenant_a"], seeded["user_a2"]) as c:
        await c.post(f"/api/remediation/{item_id}/approve", json={"notes": "ok"})
        r = await c.get(f"/api/remediation/{item_id}/history")
        history = r.json()
        transitions = [h["transition"] for h in history]
        assert transitions == ["create", "assign", "submit", "approve"], transitions
        # Actor identity is correct on each transition
        assert history[0]["actor_id"] == str(seeded["user_a1"])
        assert history[3]["actor_id"] == str(seeded["user_a2"])
