"""Cookie + CSRF integration tests for the cookie-auth migration
(see docs/design_auth_cookies.md).

What this pins (as of Phase N+2):
- `POST /portal/v1/auth/login` issues `aac_session` + `aac_csrf`
  cookies on every successful login.
- Browser callers receive `session_token: null` in the response body
  — the HttpOnly cookie is the only session secret JS could ever see.
- CLI callers opt back into the body token by sending the
  `X-Portal-Client: cli` header.
- `require_tenant_user` accepts the cookie path.
- `require_tenant_user` still accepts the Authorization: Bearer path
  (backward compat for CLI clients using the opt-in body token).
- `POST /portal/v1/me/logout` clears the cookies.
- `require_csrf` dependency exhibits lax semantics: enforces only
  when the cookie is present (Phase N+1 wired the live middleware
  with the same contract).
"""
from __future__ import annotations

import bcrypt
import pytest
import pytest_asyncio
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


# ── Scaffolding ──────────────────────────────────────────────────────


@pytest_asyncio.fixture(loop_scope="session")
async def seeded_user(pg_pool):
    """One tenant + one user with a known password.

    Returns (tenant_id, email, password) so tests can log in.
    """
    password = "Correct-Horse-Battery-Staple-99"
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("utf-8")
    async with pg_pool.acquire() as conn:
        tenant_id = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Cookie Test Tenant",
        )
        await conn.fetchval(
            """INSERT INTO tenant_users
                  (tenant_id, email, role, mfa_required, password_hash)
               VALUES ($1, $2, 'account_owner', false, $3) RETURNING id""",
            tenant_id, "cookie-user@example.com", pw_hash,
        )
    return {"tenant_id": tenant_id, "email": "cookie-user@example.com", "password": password}


@pytest_asyncio.fixture(loop_scope="session")
async def client(pg_pool):
    """ASGI test client with the test DB pool wired in and the rate
    limiter reset so login attempts don't trip 429."""
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


# ── Login issues cookies ─────────────────────────────────────────────


async def test_login_sets_session_and_csrf_cookies(client, seeded_user):
    r = await client.post(
        "/api/portal/v1/auth/login",
        json={
            "tenant_id": str(seeded_user["tenant_id"]),
            "email": seeded_user["email"],
            "password": seeded_user["password"],
        },
    )
    assert r.status_code == 201, r.text

    cookies = {c.name: c for c in r.cookies.jar}
    # COOKIE_SECURE=false in conftest → bare names, not __Host-.
    assert "aac_session" in cookies, list(cookies.keys())
    assert "aac_csrf" in cookies, list(cookies.keys())

    # Session cookie is HttpOnly + SameSite=Lax. CSRF cookie is NOT
    # HttpOnly (frontend must read it to echo via X-CSRF-Token).
    session_cookie = cookies["aac_session"]
    csrf_cookie = cookies["aac_csrf"]
    assert session_cookie.has_nonstandard_attr("HttpOnly")
    assert not csrf_cookie.has_nonstandard_attr("HttpOnly")

    # Phase N+2: browser callers (no X-Portal-Client header) receive
    # `session_token: null`. The HttpOnly cookie set above is the
    # only place the session secret lives client-side.
    body = r.json()
    assert body.get("session_token") is None
    assert body["expires_at"]


# ── require_tenant_user honors both paths ────────────────────────────


async def _login(client, user, *, as_cli: bool = False):
    """Login helper.

    Browser-style login (as_cli=False) gets only cookies. The
    bearer-path tests pass as_cli=True so the response body still
    carries `session_token` — the Phase N+2 contract is opt-in for
    CLI clients via `X-Portal-Client: cli`.
    """
    headers = {"X-Portal-Client": "cli"} if as_cli else {}
    r = await client.post(
        "/api/portal/v1/auth/login",
        json={
            "tenant_id": str(user["tenant_id"]),
            "email": user["email"],
            "password": user["password"],
        },
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r


async def test_me_via_cookie(client, seeded_user):
    """GET /portal/v1/me succeeds when only the cookie is present.

    AsyncClient persists Set-Cookie across requests on the same client,
    so a fresh GET after login carries the session cookie automatically.
    """
    await _login(client, seeded_user)
    r = await client.get("/api/portal/v1/me")
    assert r.status_code == 200, r.text
    assert r.json()["email"] == seeded_user["email"]


async def test_me_via_authorization_header(client, seeded_user):
    """Backward-compat path: explicit Authorization header still works
    for CLI clients that opt in to the body session_token.

    Clear the cookies first so the cookie path can't accidentally serve
    the request — we want to prove the header path is live.
    """
    login = await _login(client, seeded_user, as_cli=True)
    token = login.json()["session_token"]
    assert token, "CLI login should include session_token in body"
    client.cookies.clear()

    r = await client.get(
        "/api/portal/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["email"] == seeded_user["email"]


async def test_me_without_any_auth_returns_401(client):
    client.cookies.clear()
    r = await client.get("/api/portal/v1/me")
    assert r.status_code == 401


# ── Logout clears cookies ────────────────────────────────────────────


async def test_logout_clears_cookies(client, seeded_user):
    await _login(client, seeded_user)
    # Pre-state: client jar has both cookies from the login response.
    pre = {c.name for c in client.cookies.jar}
    assert "aac_session" in pre and "aac_csrf" in pre

    # Cookie-authed POST needs the matching X-CSRF-Token header
    # (Phase N+1: CsrfMiddleware enforces double-submit).
    csrf = client.cookies.get("aac_csrf")
    r = await client.post(
        "/api/portal/v1/me/logout",
        headers={"X-CSRF-Token": csrf or ""},
    )
    assert r.status_code == 200, r.text

    # FastAPI's delete_cookie emits Max-Age=0; httpx drops those names
    # from the jar. Asserting the jar directly catches the case where
    # the server-side session is revoked but the cookie isn't cleared
    # (which would still 401 on /me but for the wrong reason).
    post = {c.name for c in client.cookies.jar}
    assert "aac_session" not in post
    assert "aac_csrf" not in post


async def test_cookie_wins_when_both_cookie_and_header_present(client, seeded_user):
    """Precedence pin: cookie is checked first, header is ignored when
    the cookie carries a valid token. A future refactor that flipped
    the order would let an attacker pin a session via header even when
    the user's browser had a fresh cookie."""
    await _login(client, seeded_user)
    r = await client.get(
        "/api/portal/v1/me",
        headers={"Authorization": "Bearer obviously.invalid.token"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["email"] == seeded_user["email"]


# ── CSRF dependency ──────────────────────────────────────────────────


async def test_csrf_dependency_lax_semantics(pg_pool, seeded_user):
    """Phase N+1 semantics: the dependency enforces CSRF only when the
    `aac_csrf` cookie is present (cookie-authed request). Bearer-only
    requests pass through so CLI / non-browser clients keep working
    during the transition window.
    """
    from src.core.csrf import require_csrf

    app = FastAPI()

    @app.post("/csrf-test")
    async def _csrf_route(_: None = Depends(require_csrf)):
        return {"ok": True}

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        # No cookie, no header → bearer path, passes through.
        r = await c.post("/csrf-test")
        assert r.status_code == 200
        assert r.json() == {"ok": True}

        # Cookie set, header missing → 403 (cookie path, header required).
        c.cookies.set("aac_csrf", "the-token-value")
        r = await c.post("/csrf-test")
        assert r.status_code == 403
        assert r.json()["detail"] == "csrf token missing"

        # Cookie set, header set to a DIFFERENT value → 403 mismatch.
        r = await c.post("/csrf-test", headers={"X-CSRF-Token": "different"})
        assert r.status_code == 403
        assert r.json()["detail"] == "csrf mismatch"

        # Cookie and header match → 200.
        r = await c.post("/csrf-test", headers={"X-CSRF-Token": "the-token-value"})
        assert r.status_code == 200
        assert r.json() == {"ok": True}
