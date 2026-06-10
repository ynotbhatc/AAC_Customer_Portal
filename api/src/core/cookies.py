"""HttpOnly cookie helpers for tenant-user session + double-submit CSRF.

Phase N of the cookie-auth migration (see docs/design_auth_cookies.md):
the backend gains the cookie path while the Authorization: Bearer path
continues to work. Phase N+1 switches the frontend; Phase N+2 drops the
bearer path for browser callers.

Cookie names depend on `settings.cookie_secure`:
- `cookie_secure=True`  (prod): `__Host-aac_session`, `__Host-aac_csrf`.
  The `__Host-` prefix forces Secure + Path=/ + no Domain= — the
  strictest transport guarantees in the spec. Browsers reject the
  cookie if any of those are violated.
- `cookie_secure=False` (dev/test): `aac_session`, `aac_csrf`. Plain
  names so the cookies work over http://localhost.

`SameSite=Lax` is the right default — the SPA and API are served from
the same origin (nginx fronts both). Switching to a CDN-served SPA on
a different origin would require revisiting `SameSite=None`; flagged in
the design doc's Open Questions.
"""
from __future__ import annotations

import secrets

from fastapi import Request, Response

from .config import Settings


SESSION_COOKIE_PROD = "__Host-aac_session"
SESSION_COOKIE_DEV = "aac_session"
CSRF_COOKIE_PROD = "__Host-aac_csrf"
CSRF_COOKIE_DEV = "aac_csrf"

_CSRF_TOKEN_BYTES = 32  # 256 bits → 43 url-safe chars


def session_cookie_name(settings: Settings) -> str:
    return SESSION_COOKIE_PROD if settings.cookie_secure else SESSION_COOKIE_DEV


def csrf_cookie_name(settings: Settings) -> str:
    return CSRF_COOKIE_PROD if settings.cookie_secure else CSRF_COOKIE_DEV


def generate_csrf_token() -> str:
    return secrets.token_urlsafe(_CSRF_TOKEN_BYTES)


def set_session_cookie(
    response: Response,
    token: str,
    settings: Settings,
) -> None:
    """Write the tenant-user session cookie.

    Lifetime tracks `session_lifetime_hours` so the browser drops the
    cookie at the same moment the server-side session row expires.
    """
    response.set_cookie(
        key=session_cookie_name(settings),
        value=token,
        max_age=settings.session_lifetime_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    """Drop the session cookie. Used by logout endpoints.

    Browsers require `path` (and `secure`/`samesite` to a degree) to
    match between Set-Cookie and the delete; FastAPI's delete_cookie
    handles that.
    """
    response.delete_cookie(
        key=session_cookie_name(settings),
        path="/",
        secure=settings.cookie_secure,
        samesite="lax",
    )


def set_csrf_cookie(
    response: Response,
    settings: Settings,
    *,
    token: str | None = None,
) -> str:
    """Issue a fresh CSRF token via Set-Cookie and return the value.

    Non-HttpOnly so the frontend can read it and echo it back via the
    `X-CSRF-Token` header. Double-submit: the server validates that the
    two values match. No server-side state.

    Pass an explicit `token` to reissue a known value (e.g. when
    Phase N login wants to bind the CSRF cookie to a specific session);
    omit it to mint a fresh random one.
    """
    csrf_value = token if token is not None else generate_csrf_token()
    response.set_cookie(
        key=csrf_cookie_name(settings),
        value=csrf_value,
        max_age=settings.session_lifetime_hours * 3600,
        httponly=False,  # frontend must read this
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return csrf_value


def clear_csrf_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=csrf_cookie_name(settings),
        path="/",
        secure=settings.cookie_secure,
        samesite="lax",
    )


def read_session_cookie(request: Request, settings: Settings) -> str | None:
    return request.cookies.get(session_cookie_name(settings))


def read_csrf_cookie(request: Request, settings: Settings) -> str | None:
    return request.cookies.get(csrf_cookie_name(settings))
