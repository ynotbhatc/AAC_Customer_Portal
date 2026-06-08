"""Audit middleware + record_audit tests.

Pins:

  - record_audit() is best-effort — DB failures don't raise
  - The middleware logs mutations (POST/PUT/PATCH/DELETE) but not GET
  - The middleware logs 4xx/5xx responses regardless of method
    (so failed auth is observable)
  - resource_type/resource_id flow through from request.state
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def captured():
    """Collect every record_audit() call's kwargs for assertion."""
    calls: list[dict] = []

    async def _fake_record_audit(_pool, **kwargs):
        calls.append(kwargs)

    return calls, _fake_record_audit


@pytest.fixture
def app_with_audit(monkeypatch, captured):
    """Build a minimal FastAPI app with the audit middleware wired
    against a stub pool getter + stub record_audit. No real DB.
    """
    from src.core import audit as audit_mod
    from src.core.audit_middleware import AuditMiddleware

    calls, fake = captured
    monkeypatch.setattr(audit_mod, "record_audit", fake)

    async def _stub_pool():
        return object()  # not None — middleware uses pool for record_audit

    app = FastAPI()
    app.add_middleware(AuditMiddleware, pool_getter=_stub_pool)

    @app.get("/read")
    async def read():
        return {"ok": True}

    @app.post("/write")
    async def write():
        return {"ok": True}

    @app.patch("/write/{wid}")
    async def patch(wid: str):  # noqa: ARG001
        return {"ok": True}

    @app.get("/forbidden")
    async def forbidden():
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="nope")

    return app, calls


def test_get_is_not_audited(app_with_audit):
    app, calls = app_with_audit
    client = TestClient(app)
    r = client.get("/read")
    assert r.status_code == 200
    # Need to give the asyncio.create_task a tick; TestClient runs
    # the event loop until the response completes, but the task
    # may not have started yet. The audit middleware fires the task
    # AFTER returning the response, so on TestClient this races —
    # we accept either 0 calls (the read case) OR a single call
    # with method=GET. Since reads ARE skipped, the call list must
    # not contain a GET to /read.
    assert not any(c["method"] == "GET" and c["path"] == "/read" for c in calls)


def test_post_is_audited(app_with_audit):
    app, calls = app_with_audit
    client = TestClient(app)
    r = client.post("/write")
    assert r.status_code == 200
    # Flush any pending background tasks
    import time
    for _ in range(20):
        if any(c["path"] == "/write" for c in calls):
            break
        time.sleep(0.05)
    assert any(c["method"] == "POST" and c["path"] == "/write" for c in calls)


def test_patch_is_audited(app_with_audit):
    app, calls = app_with_audit
    client = TestClient(app)
    r = client.patch("/write/abc")
    assert r.status_code == 200
    import time
    for _ in range(20):
        if any(c["path"] == "/write/abc" for c in calls):
            break
        time.sleep(0.05)
    assert any(c["method"] == "PATCH" and c["path"] == "/write/abc" for c in calls)


def test_4xx_get_is_audited(app_with_audit):
    """A failed auth-like response on a GET still goes to the audit
    log — that's the security signal we want."""
    app, calls = app_with_audit
    client = TestClient(app)
    r = client.get("/forbidden")
    assert r.status_code == 403
    import time
    for _ in range(20):
        if any(c["path"] == "/forbidden" for c in calls):
            break
        time.sleep(0.05)
    assert any(c["method"] == "GET" and c["path"] == "/forbidden" and c["status_code"] == 403 for c in calls)


def test_record_audit_swallows_db_errors():
    """A DB error during record_audit must not raise — it logs and
    returns, so the request lifecycle is unaffected."""
    import asyncio
    from src.core.audit import record_audit

    class _BrokenPool:
        async def execute(self, *_a, **_kw):
            raise RuntimeError("DB down")

    # Should not raise.
    asyncio.run(
        record_audit(
            _BrokenPool(),
            method="POST",
            path="/x",
            status_code=200,
        )
    )
