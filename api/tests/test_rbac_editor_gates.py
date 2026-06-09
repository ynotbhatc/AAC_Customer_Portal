"""Pin the editor/account_owner gate on mutating endpoints.

Roadmap target (docs/security_roadmap.md, "RBAC enforcement"):
viewers can read but not write. This test verifies the wiring by
hitting a representative gated endpoint on each affected router with
a viewer role and asserting 403.

Unit coverage on the pure helper (`has_role`) ensures the hierarchy
math is right; the integration paths verify the FastAPI dependency
is actually attached to the route.
"""
from __future__ import annotations

from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.core.rbac import Role, has_role


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


# ── Unit: pure hierarchy math ─────────────────────────────────────────


def test_has_role_hierarchy_orders_viewer_editor_owner():
    assert Role.VIEWER < Role.EDITOR < Role.ACCOUNT_OWNER


def test_has_role_viewer_blocks_editor_and_owner():
    assert not has_role("viewer", "editor")
    assert not has_role("viewer", "account_owner")


def test_has_role_editor_passes_editor_blocks_owner():
    assert has_role("editor", "editor")
    assert not has_role("editor", "account_owner")


def test_has_role_owner_passes_everything():
    assert has_role("account_owner", "viewer")
    assert has_role("account_owner", "editor")
    assert has_role("account_owner", "account_owner")


# ── Integration: viewer gets 403 from gated endpoints ─────────────────


def _client_for(role: str):
    """Build a client whose session has the given role. Both
    require_tenant_user and require_tenant_user_mfa are overridden so
    the role check is the only gate exercised."""
    from main import app
    from src.core.sessions import require_tenant_user, require_tenant_user_mfa

    tenant_id = uuid4()
    user_id = uuid4()
    fake = {
        "session_id": UUID("11111111-1111-1111-1111-111111111111"),
        "tenant_id": tenant_id,
        "tenant_user_id": user_id,
        "email": "u@example",
        "display_name": "u",
        "role": role,
        "mfa_required": False,
        "mfa_enrolled": True,
        "mfa_verified": True,
    }

    async def _user_dep(request=None):
        if request is not None:
            request.state.tenant_user = fake
        return fake

    app.dependency_overrides[require_tenant_user] = _user_dep
    app.dependency_overrides[require_tenant_user_mfa] = _user_dep
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test"), app


@pytest_asyncio.fixture(loop_scope="session")
async def viewer_client():
    client, app = _client_for("viewer")
    try:
        yield client
    finally:
        app.dependency_overrides.clear()
        await client.aclose()


# Representative gated endpoints — one per router that adopts the
# editor gate. The body shapes don't matter; the role check fires
# before any body validation.
_VIEWER_403_TARGETS = [
    ("POST", "/api/portal/v1/me/policies/upload"),
    ("POST", "/api/portal/v1/me/policies/fork"),
    ("POST", "/api/portal/v1/me/bundles/build"),
    ("POST", "/api/aap/launch"),
    ("POST", "/api/portal/v1/me/baselines"),
]


@pytest.mark.parametrize("method,path", _VIEWER_403_TARGETS)
async def test_viewer_role_is_blocked_403(viewer_client, method, path):
    resp = await viewer_client.request(method, path, json={})
    assert resp.status_code == 403, (
        f"{method} {path}: expected 403, got {resp.status_code} {resp.text[:200]}"
    )
    assert "editor" in resp.text or "role" in resp.text


async def test_unknown_role_is_blocked_403(viewer_client):
    """Defensive: a session with an unrecognized role string must NOT
    be silently treated as elevated. require_role raises ValueError
    inside has_role; that surfaces as a 500. Either 403 or 500 is
    fail-closed — what's not acceptable is 2xx."""
    # Build a fresh client with a bogus role.
    from main import app
    from src.core.sessions import require_tenant_user, require_tenant_user_mfa

    async def _user_dep(request=None):
        fake = {
            "tenant_id": uuid4(),
            "tenant_user_id": uuid4(),
            "role": "superduperadmin",
            "mfa_required": False,
            "mfa_verified": True,
        }
        if request is not None:
            request.state.tenant_user = fake
        return fake

    app.dependency_overrides[require_tenant_user] = _user_dep
    app.dependency_overrides[require_tenant_user_mfa] = _user_dep
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/api/portal/v1/me/policies/upload", json={})
    app.dependency_overrides.clear()

    assert resp.status_code >= 400 and resp.status_code < 600, (
        f"unknown role must fail closed, got {resp.status_code}"
    )
    assert resp.status_code != 401  # not an auth issue, it's a role issue
