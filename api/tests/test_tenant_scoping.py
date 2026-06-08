"""Multi-tenant scoping of compliance reads — P0-A2.

Pins:

  - allowed_hostnames() returns the right set per tenant
  - Compliance endpoints with an empty allowed set return []
  - Caller-supplied hostname filter that's NOT in the allowed set
    returns [] (no info-leak via hostname guessing)
  - get_result by id returns 404 when the row's hostname isn't in
    the tenant's allowed set (no info-leak via id guessing)
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def fixed_user():
    return {
        "session_id": "11111111-1111-1111-1111-111111111111",
        "tenant_user_id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": "33333333-3333-3333-3333-333333333333",
        "email": "u@example.com",
        "display_name": "u",
        "role": "user",
        "mfa_required": False,
        "mfa_enrolled": False,
        "mfa_verified": False,
    }


@pytest.fixture
def client_with_tenant(fixed_user):
    """Build a TestClient where:
      - require_tenant_user returns fixed_user
      - portal pool is stubbed and returns a fixed allowed-hostnames set
      - compliance pool is stubbed; tracks the queries it received
    """
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.core.database import get_pool
    from src.core.sessions import require_tenant_user

    captured_queries: list[tuple[str, tuple]] = []

    class _CompliancePool:
        async def fetch(self, query, *args):
            captured_queries.append((query, args))
            # Return empty result by default — tests assert on the
            # query shape (allowed-hostnames passed in), not the
            # actual rows.
            return []

        async def fetchrow(self, query, *args):
            captured_queries.append((query, args))
            return None

    class _PortalPool:
        # Used by allowed_hostnames(). We stub fetch to return
        # exactly the hostnames we want this tenant to see.
        def __init__(self, hostnames: list[str]):
            self.hostnames = hostnames

        async def fetch(self, query, *args):
            return [{"hostname": h} for h in self.hostnames]

    state = {"allowed": ["host-a", "host-b"], "captured": captured_queries}

    async def _portal_pool():
        return _PortalPool(state["allowed"])

    async def _compliance_pool():
        return _CompliancePool()

    app.dependency_overrides[get_portal_pool] = _portal_pool
    app.dependency_overrides[get_pool] = _compliance_pool
    app.dependency_overrides[require_tenant_user] = lambda: fixed_user

    try:
        yield TestClient(app), state
    finally:
        for d in (get_portal_pool, get_pool, require_tenant_user):
            app.dependency_overrides.pop(d, None)


def test_results_includes_tenant_hostnames_in_query(client_with_tenant):
    client, state = client_with_tenant
    r = client.get("/api/compliance/results")
    assert r.status_code == 200
    assert r.json() == []  # stub returns empty
    # The compliance query should have received the allowed-hostnames
    # list as its first arg.
    assert state["captured"], "compliance pool was never queried"
    _query, args = state["captured"][0]
    assert args[0] == ["host-a", "host-b"], f"unexpected args: {args}"


def test_results_with_empty_allowed_returns_empty_without_querying_compliance(client_with_tenant):
    client, state = client_with_tenant
    state["allowed"] = []
    # Important: this assertion verifies the compliance DB is NEVER
    # touched when the tenant has no mapped hosts — defense-in-depth
    # against a leak if the WHERE clause were ever wrong.
    state["captured"].clear()
    r = client.get("/api/compliance/results")
    assert r.status_code == 200
    assert r.json() == []
    assert state["captured"] == [], "compliance pool was queried with empty allowed set"


def test_results_with_disallowed_hostname_returns_empty(client_with_tenant):
    """Caller passes ?hostname=foreign-host. They get [] — no info
    leak about whether 'foreign-host' exists."""
    client, state = client_with_tenant
    state["captured"].clear()
    r = client.get("/api/compliance/results?hostname=foreign-host")
    assert r.status_code == 200
    assert r.json() == []
    assert state["captured"] == [], "compliance pool was queried for a disallowed hostname"


def test_get_result_for_disallowed_hostname_returns_404(client_with_tenant):
    """Even with a valid id, get_result returns 404 if the row's
    hostname is outside the tenant's allowed set. The compliance
    query's WHERE clause carries hostname = ANY($2::text[])."""
    client, state = client_with_tenant
    r = client.get("/api/compliance/results/9999")
    assert r.status_code == 404
    # Should have queried compliance with allowed_hostnames included
    assert state["captured"], "compliance pool was never queried"
    _q, args = state["captured"][0]
    assert args[0] == 9999
    assert args[1] == ["host-a", "host-b"]


def test_frameworks_filters_by_allowed_hostnames(client_with_tenant):
    client, state = client_with_tenant
    r = client.get("/api/compliance/frameworks")
    assert r.status_code == 200
    _q, args = state["captured"][0]
    assert args[0] == ["host-a", "host-b"]


def test_hosts_filters_by_allowed_hostnames(client_with_tenant):
    client, state = client_with_tenant
    r = client.get("/api/compliance/hosts")
    assert r.status_code == 200
    _q, args = state["captured"][0]
    assert args[0] == ["host-a", "host-b"]


def test_trend_filters_by_allowed_hostnames(client_with_tenant):
    client, state = client_with_tenant
    r = client.get("/api/compliance/trend?framework=cis_rhel9")
    assert r.status_code == 200
    _q, args = state["captured"][0]
    # framework=$1, days=$2, allowed=$3
    assert args[0] == "cis_rhel9"
    assert args[2] == ["host-a", "host-b"]
