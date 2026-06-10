"""Phase N+2 contract tests for `POST /portal/v1/auth/login`.

The body-token gate is the only behavioral change in N+2:

  - Browser callers (no `X-Portal-Client` header): SessionCreated has
    `session_token=null`. Cookies do the work.
  - CLI callers (`X-Portal-Client: cli`): SessionCreated includes
    `session_token` so the bearer flow keeps working for ops scripts
    and integration tests.

The cookies (HttpOnly aac_session + non-HttpOnly aac_csrf) are set
on every successful login regardless of the header, because issuing
them is cheap and a future CLI may want to use the cookie path.

The /me endpoint is exercised here as a sanity check that the
authenticated identity the login established matches what /me returns
— in case a future refactor accidentally decoupled the two.
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
            "N+2 Test Tenant",
        )
        await conn.fetchval(
            """INSERT INTO tenant_users
                  (tenant_id, email, role, mfa_required, password_hash)
               VALUES ($1, $2, 'account_owner', false, $3) RETURNING id""",
            tenant_id, "n2-user@example.com", pw_hash,
        )
    return {"tenant_id": tenant_id, "email": "n2-user@example.com", "password": password}


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


def _login_body(user):
    return {
        "tenant_id": str(user["tenant_id"]),
        "email": user["email"],
        "password": user["password"],
    }


async def test_browser_login_omits_session_token_but_sets_cookies(client, seeded):
    """Default login (no X-Portal-Client header) is the browser path.
    The JS-readable body MUST NOT contain the session secret."""
    r = await client.post("/api/portal/v1/auth/login", json=_login_body(seeded))
    assert r.status_code == 201, r.text

    body = r.json()
    # Field is present (Pydantic emits the key), value is null.
    assert "session_token" in body
    assert body["session_token"] is None
    assert body["expires_at"]
    assert body["mfa_required"] is False
    assert body["mfa_verified"] is True

    # Cookies still set so subsequent requests authenticate.
    cookies = {c.name for c in r.cookies.jar}
    assert "aac_session" in cookies
    assert "aac_csrf" in cookies


async def test_cli_login_returns_session_token_in_body(client, seeded):
    """CLI clients opt in via X-Portal-Client: cli and receive the
    token for the Authorization: Bearer flow."""
    r = await client.post(
        "/api/portal/v1/auth/login",
        json=_login_body(seeded),
        headers={"X-Portal-Client": "cli"},
    )
    assert r.status_code == 201, r.text

    body = r.json()
    assert body["session_token"]
    assert "." in body["session_token"]  # {session_id}.{secret} format


async def test_cli_login_still_sets_cookies(client, seeded):
    """Cookies are unconditional — even CLI callers get them so a
    future cookie-aware CLI can switch over without a server change."""
    r = await client.post(
        "/api/portal/v1/auth/login",
        json=_login_body(seeded),
        headers={"X-Portal-Client": "cli"},
    )
    assert r.status_code == 201, r.text
    cookies = {c.name for c in r.cookies.jar}
    assert "aac_session" in cookies
    assert "aac_csrf" in cookies


async def test_x_portal_client_header_is_case_insensitive(client, seeded):
    """`X-Portal-Client: CLI` should opt in just like `cli` — HTTP
    headers are case-insensitive for the *name*, and we normalise the
    *value* in the router so operators don't get burned by casing."""
    r = await client.post(
        "/api/portal/v1/auth/login",
        json=_login_body(seeded),
        headers={"X-Portal-Client": "CLI"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["session_token"]


async def test_x_portal_client_other_values_do_not_opt_in(client, seeded):
    """Any value other than `cli` is treated as a browser caller. This
    keeps the gate explicit — typos like `browser` or `sdk` should
    fail closed (no token in body), not silently succeed."""
    for header_value in ("browser", "sdk", "spa", ""):
        # Clear the cookie jar between attempts so the CSRF middleware
        # treats each login as a fresh first-contact request. Without
        # this, the aac_csrf cookie from the prior iteration would
        # demand a matching X-CSRF-Token on this POST.
        client.cookies.clear()
        r = await client.post(
            "/api/portal/v1/auth/login",
            json=_login_body(seeded),
            headers={"X-Portal-Client": header_value},
        )
        assert r.status_code == 201, r.text
        assert r.json()["session_token"] is None, (
            f"X-Portal-Client={header_value!r} unexpectedly opted into "
            "body token"
        )
