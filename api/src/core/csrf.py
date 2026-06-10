"""Double-submit CSRF dependency for cookie-authenticated requests.

Pattern:
- Server issues two cookies at login: HttpOnly session + non-HttpOnly CSRF.
- Frontend reads the CSRF cookie and echoes it via `X-CSRF-Token` on
  state-changing requests (POST/PATCH/DELETE).
- This dependency verifies the header matches the cookie.

A cross-site attacker can forge a request to the API but can neither
set the CSRF cookie on the user's behalf nor read it cross-origin —
so they cannot satisfy both halves of the double-submit. OWASP-
recommended for SPAs because it requires no server-side state.

Phase N (this PR) ships the dependency but does NOT yet apply it to
any real endpoint. Phase N+1 attaches it to mutating routes after the
frontend starts sending the header. A unit test exercises the
dependency directly so regressions surface immediately.

GET / HEAD / OPTIONS are not CSRF targets (no state change); endpoints
on those methods don't need `Depends(require_csrf)`.
"""
from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request

from .config import Settings, get_settings
from .cookies import read_csrf_cookie


CSRF_HEADER = "X-CSRF-Token"


async def require_csrf(
    request: Request,
    x_csrf_token: Annotated[str | None, Header(alias=CSRF_HEADER)] = None,
    settings: Annotated[Settings, Depends(get_settings)] = None,  # type: ignore[assignment]
) -> None:
    """Reject requests whose CSRF header doesn't match the cookie.

    Both sides must be present and equal. Uses `hmac.compare_digest`
    for the comparison so a timing oracle can't whittle the cookie
    value out one byte at a time.
    """
    cookie_value = read_csrf_cookie(request, settings)
    if not cookie_value or not x_csrf_token:
        raise HTTPException(status_code=403, detail="csrf token missing")
    if not hmac.compare_digest(cookie_value, x_csrf_token):
        raise HTTPException(status_code=403, detail="csrf mismatch")
