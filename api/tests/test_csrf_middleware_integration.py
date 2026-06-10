"""End-to-end CSRF middleware tests against the real FastAPI app.

Phase N+1 enforces double-submit CSRF on every mutating request that
is authenticated by cookie. Bearer-authed requests (no aac_csrf
cookie) pass through — that's the backward-compatibility lane for
CLI clients and pre-N+1 SPA builds.

These tests exercise the middleware on `/api/portal/v1/me/logout`
(POST) because it's a tenant-user endpoint we already have wired,
needs auth, and is harmless to call repeatedly.
"""
from __future__ import annotations

import bcrypt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


@pytest_asyncio.fixture(loop_scope="session")
async def seeded(pg_pool):
    password = "Correct-Horse-Battery-Staple-99"
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode()
    async with pg_pool.acquire() as conn:
        tenant_id = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "CSRF Test Tenant",
        )
        await conn.fetchval(
            """INSERT INTO tenant_users
                  (tenant_id, email, role, mfa_required, password_hash)
               VALUES ($1, $2, 'account_owner', false, $3) RETURNING id""",
            tenant_id, "csrf-user@example.com", pw_hash,
        )
    return {"tenant_id": tenant_id, "email": "csrf-user@example.com", "password": password}


@pytest_asyncio.fixture(loop_scope="session")
async def client(pg_pool):
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


async def _login(client, user):
    r = await client.post(
        "/api/portal/v1/auth/login",
        json={
            "tenant_id": str(user["tenant_id"]),
            "email": user["email"],
            "password": user["password"],
        },
    )
    assert r.status_code == 201, r.text
    return r


async def test_cookie_authed_post_without_csrf_header_is_blocked(client, seeded):
    """The SPA path: cookie authentication is in effect, the
    middleware demands the matching X-CSRF-Token header."""
    await _login(client, seeded)
    # Drop the CSRF header but keep the cookie jar (login set both
    # cookies; we just don't echo the header).
    r = await client.post("/api/portal/v1/me/logout")
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "csrf token missing"


async def test_cookie_authed_post_with_matching_header_passes(client, seeded):
    await _login(client, seeded)
    csrf = client.cookies.get("aac_csrf")
    assert csrf, "login should have set the aac_csrf cookie"
    r = await client.post(
        "/api/portal/v1/me/logout",
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 200, r.text


async def test_cookie_authed_post_with_mismatched_header_is_blocked(client, seeded):
    await _login(client, seeded)
    r = await client.post(
        "/api/portal/v1/me/logout",
        headers={"X-CSRF-Token": "not-the-real-token"},
    )
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "csrf mismatch"


async def test_bearer_only_post_passes_without_csrf_header(client, seeded):
    """Backward-compat: a request without the aac_csrf cookie is on
    the bearer path. The middleware does not enforce CSRF on it —
    bearer tokens are themselves cross-origin proof (the attacker
    can't read them from the user's browser).

    Note: this DOES revoke the session — fine for the assertion."""
    login = await _login(client, seeded)
    token = login.json()["session_token"]
    client.cookies.clear()
    r = await client.post(
        "/api/portal/v1/me/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text


async def test_cookie_authed_get_passes_without_csrf_header(client, seeded):
    """Read methods aren't CSRF targets — GET passes through."""
    await _login(client, seeded)
    r = await client.get("/api/portal/v1/me")
    assert r.status_code == 200, r.text
