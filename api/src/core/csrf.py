"""CSRF middleware + dependency for cookie-authenticated requests.

Phase N+1 of the cookie-auth migration (see docs/design_auth_cookies.md):
the backend enforces double-submit CSRF on every state-changing
request that is *authenticated by cookie*. Bearer-authenticated
requests (no `aac_csrf` cookie present) pass through — CLI clients
and pre-N+1 SPA builds are not CSRF targets because the attacker
can't read the bearer token cross-origin.

Why middleware, not per-route dependency:
- One attachment point in main.py vs. patching ~30+ mutating routes.
- Future endpoints get covered automatically; nobody has to remember
  to attach `Depends(require_csrf)`.

Method gate: only POST / PATCH / DELETE / PUT carry state-change
risk. GET / HEAD / OPTIONS pass through unconditionally.

Cookie gate: if `aac_csrf` (or `__Host-aac_csrf` in prod) is NOT
present on the request, we assume the caller is on the bearer path
and let the request through. Phase N+2 will drop the bearer path
for browser callers and make the cookie path mandatory.
"""
from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .config import Settings, get_settings
from .cookies import read_csrf_cookie


CSRF_HEADER = "X-CSRF-Token"
_MUTATING_METHODS = frozenset({"POST", "PATCH", "DELETE", "PUT"})


class CsrfMiddleware(BaseHTTPMiddleware):
    """Reject cookie-authed mutating requests whose CSRF header is
    missing or doesn't match the cookie.

    The middleware does not authenticate — it only enforces the
    double-submit pairing. A request without the `aac_csrf` cookie
    is presumed bearer-authenticated and passes through.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method in _MUTATING_METHODS:
            settings = get_settings()
            cookie_value = read_csrf_cookie(request, settings)
            if cookie_value:
                header = request.headers.get(CSRF_HEADER)
                if not header:
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "csrf token missing"},
                    )
                if not hmac.compare_digest(cookie_value, header):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "csrf mismatch"},
                    )
        return await call_next(request)


async def require_csrf(
    request: Request,
    x_csrf_token: Annotated[str | None, Header(alias=CSRF_HEADER)] = None,
    settings: Annotated[Settings, Depends(get_settings)] = None,  # type: ignore[assignment]
) -> None:
    """Per-route CSRF dependency. Same semantics as the middleware
    (bearer path passes through) but explicit at the call site.

    The middleware covers the broad case. This dependency stays for
    routes that want a documented, explicit declaration — e.g. a new
    state-changing endpoint where the author wants the dependency to
    appear in the OpenAPI schema.
    """
    cookie_value = read_csrf_cookie(request, settings)
    if not cookie_value:
        # Bearer path — no cookie, no CSRF risk to enforce here.
        return
    if not x_csrf_token:
        raise HTTPException(status_code=403, detail="csrf token missing")
    if not hmac.compare_digest(cookie_value, x_csrf_token):
        raise HTTPException(status_code=403, detail="csrf mismatch")
