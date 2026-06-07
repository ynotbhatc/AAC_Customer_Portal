"""Auth gating on legacy + stub routers.

Before P0-A, the compliance/* routes and the 3 stub routers
(/remediation, /reports/download, /aap/launch) were openly readable
by anyone who could reach the API port. This test pins the gate:
every endpoint returns 401 when called without a session token, and
the WRITE endpoints additionally require an MFA-verified session.

We don't need a real DB or a real session here — just an
unauthenticated call to each route. The dependency rejects before
any DB access.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Override get_portal_pool so the auth dependency can resolve
    its `pool` param without a real DB connection. The pool stub is
    never actually used — require_tenant_user raises 401 on missing
    Authorization header before touching it."""
    from main import app
    from src.core.portal_db import get_portal_pool

    async def _stub_pool():
        return None  # never used; 401 fires first

    app.dependency_overrides[get_portal_pool] = _stub_pool
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_portal_pool, None)


# ── Anonymous calls must 401 on every gated endpoint ────────────────


READ_ENDPOINTS = [
    ("GET", "/api/compliance/results"),
    ("GET", "/api/compliance/results/1"),
    ("GET", "/api/compliance/frameworks"),
    ("GET", "/api/compliance/hosts"),
    ("GET", "/api/compliance/trend", {"framework": "cis_rhel9"}),
    ("GET", "/api/remediation"),
    ("GET", "/api/reports/download", {"framework": "cis_rhel9"}),
]


WRITE_ENDPOINTS = [
    ("PATCH", "/api/remediation/abc-123"),
    ("POST", "/api/aap/launch"),
]


@pytest.mark.parametrize("entry", READ_ENDPOINTS, ids=lambda e: f"{e[0]}_{e[1]}")
def test_read_endpoints_require_auth(client, entry):
    method, path = entry[0], entry[1]
    params = entry[2] if len(entry) > 2 else None
    r = client.request(method, path, params=params)
    assert r.status_code == 401, (
        f"{method} {path} must 401 without a session — got {r.status_code} "
        f"{r.text[:200]}"
    )


@pytest.mark.parametrize("entry", WRITE_ENDPOINTS, ids=lambda e: f"{e[0]}_{e[1]}")
def test_write_endpoints_require_auth(client, entry):
    method, path = entry[0], entry[1]
    r = client.request(method, path, json={})
    # 401 (no session) is the right answer for an anonymous caller.
    # We don't separately exercise "logged-in but no MFA" → 403 here
    # because that requires a real session; covered by the
    # require_tenant_user_mfa tests in the existing portal_users
    # integration suite.
    assert r.status_code == 401, (
        f"{method} {path} must 401 without a session — got {r.status_code} "
        f"{r.text[:200]}"
    )
