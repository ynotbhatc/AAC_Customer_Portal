"""Integration tests for the slowapi-backed rate limiter.

Pins the contract that auth endpoints carry tight per-route limits
(login and totp/verify at 10/minute, password-reset/confirm at
5/minute) on top of the default per-IP global. The exact behaviour
under load is covered by slowapi's own tests — this suite verifies
that the decorators are wired and that the 429 response shape is
what callers should expect.

Resets the limiter between tests so order doesn't matter.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest_asyncio.fixture(loop_scope="session")
async def client(pg_pool):
    """AsyncClient over the real ASGI app with the test DB pool
    wired in. Limiter counters are reset before yielding so a single
    test gets a clean window."""
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.core.rate_limit import _reset

    async def _get_pool():
        return pg_pool

    await _reset()

    app.dependency_overrides[get_portal_pool] = _get_pool
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c
    finally:
        app.dependency_overrides.clear()
        await _reset()


async def test_login_429s_after_10_requests_in_a_minute(client):
    """The 11th login attempt within a minute should return 429.

    The body is deliberately invalid (no real tenant/email) so each
    pre-limit request returns 401 — that's fine; the limiter triggers
    on the count of requests, not the outcome.
    """
    body = {
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "email": "nobody@nowhere.example",
        "password": "definitely-not-a-real-password",
    }
    statuses: list[int] = []
    for _ in range(12):
        r = await client.post("/api/portal/v1/auth/login", json=body)
        statuses.append(r.status_code)

    pre_limit = statuses[:10]
    post_limit = statuses[10:]
    assert all(s == 401 for s in pre_limit), (
        f"first 10 requests should hit the 401 path, got {pre_limit}"
    )
    assert any(s == 429 for s in post_limit), (
        f"requests 11+ should include at least one 429, got {post_limit}"
    )


async def test_password_reset_confirm_429s_after_5(client):
    """Reset-confirm sits at 5/minute — even tighter than login because
    a reset token grants password change."""
    body = {"reset_token": "bogus.token", "new_password": "x" * 16}
    statuses: list[int] = []
    for _ in range(7):
        r = await client.post(
            "/api/portal/v1/auth/password-reset/confirm", json=body
        )
        statuses.append(r.status_code)
    # First 5 fall through to the "malformed reset token" 400 path.
    # The 6th-or-later should include a 429.
    assert any(s == 429 for s in statuses[5:]), (
        f"requests 6+ should include 429, got {statuses}"
    )


async def test_rate_limit_429_body_is_json(client):
    """Pin the response shape callers see when they get rate-limited
    — JSON with a `detail` field, not an HTML 429 page."""
    body = {
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "email": "nobody@nowhere.example",
        "password": "x" * 16,
    }
    for _ in range(11):
        r = await client.post("/api/portal/v1/auth/login", json=body)
    # The 11th MUST be 429 (limit is 10/minute).
    assert r.status_code == 429, r.text
    assert r.headers.get("content-type", "").startswith("application/json")
    payload = r.json()
    assert "detail" in payload or "error" in payload
