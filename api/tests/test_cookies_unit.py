"""Unit tests for `core.cookies` — pure-function: no DB, no app.

Pins the Set-Cookie attributes that the Phase N migration depends on:
HttpOnly on the session cookie, NOT HttpOnly on the CSRF cookie,
SameSite=Lax, and the prod-vs-dev cookie-name switch.
"""
from __future__ import annotations

from fastapi import Response

from src.core.config import Settings
from src.core.cookies import (
    CSRF_COOKIE_DEV,
    CSRF_COOKIE_PROD,
    SESSION_COOKIE_DEV,
    SESSION_COOKIE_PROD,
    clear_csrf_cookie,
    clear_session_cookie,
    csrf_cookie_name,
    generate_csrf_token,
    session_cookie_name,
    set_csrf_cookie,
    set_session_cookie,
)


def _make_settings(*, secure: bool) -> Settings:
    return Settings(
        pg_password="x",
        portal_pg_password="x",
        secret_key="x",
        cookie_secure=secure,
    )


def test_cookie_name_switch_prod_vs_dev():
    prod = _make_settings(secure=True)
    dev = _make_settings(secure=False)
    assert session_cookie_name(prod) == SESSION_COOKIE_PROD == "__Host-aac_session"
    assert csrf_cookie_name(prod) == CSRF_COOKIE_PROD == "__Host-aac_csrf"
    assert session_cookie_name(dev) == SESSION_COOKIE_DEV == "aac_session"
    assert csrf_cookie_name(dev) == CSRF_COOKIE_DEV == "aac_csrf"


def test_generate_csrf_token_is_random_and_long_enough():
    a = generate_csrf_token()
    b = generate_csrf_token()
    assert a != b
    assert len(a) >= 32  # 256-bit url-safe → 43 chars; floor at 32 for safety


def test_set_session_cookie_is_httponly_lax_with_max_age():
    s = _make_settings(secure=False)
    r = Response()
    set_session_cookie(r, "the.session.token", s)
    header = r.headers["set-cookie"]
    assert "aac_session=the.session.token" in header
    assert "HttpOnly" in header
    assert "SameSite=lax" in header
    # Max-Age tracks session_lifetime_hours * 3600 (default 12h).
    assert f"Max-Age={s.session_lifetime_hours * 3600}" in header
    assert "Path=/" in header
    # Secure must NOT be set in dev/test config — http://localhost has
    # to actually receive the cookie.
    assert "Secure" not in header


def test_set_session_cookie_marks_secure_in_prod():
    s = _make_settings(secure=True)
    r = Response()
    set_session_cookie(r, "the.session.token", s)
    header = r.headers["set-cookie"]
    assert "__Host-aac_session=the.session.token" in header
    assert "Secure" in header
    assert "HttpOnly" in header


def test_set_csrf_cookie_is_not_httponly_and_returns_value():
    s = _make_settings(secure=False)
    r = Response()
    issued = set_csrf_cookie(r, s)
    header = r.headers["set-cookie"]
    assert f"aac_csrf={issued}" in header
    # The frontend reads it, so HttpOnly MUST NOT be set.
    assert "HttpOnly" not in header
    assert "SameSite=lax" in header


def test_set_csrf_cookie_accepts_explicit_token():
    s = _make_settings(secure=False)
    r = Response()
    returned = set_csrf_cookie(r, s, token="my-fixed-token")
    assert returned == "my-fixed-token"
    assert "aac_csrf=my-fixed-token" in r.headers["set-cookie"]


def test_clear_helpers_emit_delete_headers():
    s = _make_settings(secure=False)
    r = Response()
    clear_session_cookie(r, s)
    clear_csrf_cookie(r, s)
    # FastAPI delete_cookie sets value="" + Max-Age=0.
    headers = r.headers.getlist("set-cookie")
    assert any('aac_session=""' in h and "Max-Age=0" in h for h in headers)
    assert any('aac_csrf=""' in h and "Max-Age=0" in h for h in headers)
