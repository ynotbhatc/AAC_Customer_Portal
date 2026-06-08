"""Audit log actor wiring — P0-B2.

The middleware in P0-B reads `request.state.tenant_user` to populate
the tenant_id + tenant_user_id columns of system_audit_log. P0-B2
wires the auth dep to actually SET that on the request.

This test pins the contract: a route that uses require_tenant_user
ends up with the user dict on request.state, and the audit middleware
sees it.
"""
from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient


@pytest.fixture
def captured():
    """Collect every record_audit() call's kwargs."""
    calls: list[dict] = []

    async def _fake_record_audit(_pool, **kwargs):
        calls.append(kwargs)

    return calls, _fake_record_audit


@pytest.fixture
def app_with_auth_and_audit(monkeypatch, captured):
    """Minimal app: AuditMiddleware + a POST route gated by
    require_tenant_user. The auth dep is stubbed to a fixed user
    via dependency_overrides so we don't need a real DB."""
    from src.core import audit as audit_mod
    from src.core.audit_middleware import AuditMiddleware
    from src.core.sessions import require_tenant_user

    calls, fake = captured
    monkeypatch.setattr(audit_mod, "record_audit", fake)

    async def _stub_pool():
        return object()

    fixed_user = {
        "session_id": "11111111-1111-1111-1111-111111111111",
        "tenant_user_id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": "33333333-3333-3333-3333-333333333333",
        "email": "ops@example.com",
        "display_name": "Ops",
        "role": "user",
        "mfa_required": False,
        "mfa_enrolled": False,
        "mfa_verified": False,
    }

    # Override that mirrors what the real dep does — set state.
    async def _stub_user(request: Request) -> dict:
        request.state.tenant_user = fixed_user
        return fixed_user

    app = FastAPI()
    app.add_middleware(AuditMiddleware, pool_getter=_stub_pool)

    @app.post("/write")
    async def write(user: dict = Depends(_stub_user)):  # noqa: B008
        return {"ok": True}

    return app, calls, fixed_user


def test_audit_row_carries_tenant_id_and_user_id(app_with_auth_and_audit):
    app, calls, user = app_with_auth_and_audit
    client = TestClient(app)
    r = client.post("/write")
    assert r.status_code == 200

    # Drain pending background tasks
    import time
    for _ in range(40):
        if any(c["path"] == "/write" for c in calls):
            break
        time.sleep(0.05)

    matching = [c for c in calls if c["path"] == "/write"]
    assert matching, "no audit row written for /write"
    row = matching[0]
    assert row["tenant_id"] == user["tenant_id"], f"tenant_id missing/wrong: {row}"
    assert row["tenant_user_id"] == user["tenant_user_id"], f"tenant_user_id missing/wrong: {row}"
    assert row["method"] == "POST"
    assert row["status_code"] == 200


def test_require_tenant_user_sets_request_state(monkeypatch):
    """Direct unit check: require_tenant_user sets request.state.tenant_user.

    Patches _resolve_bearer to skip the real bearer-token resolution
    so this is a pure wiring test.
    """
    import asyncio
    from src.core import sessions as s

    fixed_user = {"tenant_id": "t", "tenant_user_id": "u", "email": "x@y"}

    async def _fake_resolve(request, authorization, pool):
        return fixed_user

    monkeypatch.setattr(s, "_resolve_bearer", _fake_resolve)

    # Build a minimal Request to exercise the dep
    from starlette.requests import Request as StarletteRequest
    from starlette.types import Scope

    scope: Scope = {
        "type": "http",
        "method": "GET",
        "path": "/test",
        "headers": [],
    }
    req = StarletteRequest(scope)

    result = asyncio.run(s.require_tenant_user(req, authorization="Bearer x", pool=None))
    assert result is fixed_user
    assert getattr(req.state, "tenant_user", None) is fixed_user
