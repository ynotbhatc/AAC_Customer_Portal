# Design — HttpOnly Cookies + CSRF for Browser Auth

**Status:** draft for review — implementation deferred pending decisions
on this doc.

## Problem

Three browser-facing tokens currently live in `localStorage`
(`frontend/src/lib/auth.ts:3-4, 33-35, 46-69`):

- Operator **admin token** — gates `/api/admin/v1/...` endpoints
- Tenant **session token** — gates `/api/portal/v1/me/...` endpoints
- (Tenant token *secret* — operator-issued for the AAC bridge — also
  shows once in the UI and is copy-pasted into the bridge config; this
  one stays as bearer, see § Out of scope)

`localStorage` is readable by any JavaScript that runs on the page.
A single XSS payload — bypassed CSP, an unsanitized field, a
compromised npm dep — exfiltrates all tokens stored there. The
mitigation is to put auth state in **HttpOnly cookies** so JS can't
read it, then add CSRF protection for state-changing requests
(because cookies are sent automatically with cross-origin requests,
which is what XSRF exploits).

## Recommendation

Move both browser tokens to HttpOnly, Secure, SameSite=Lax cookies.
Add a double-submit CSRF token pattern: the server issues a non-HttpOnly
`csrf` cookie at login; the frontend echoes its value back via the
`X-CSRF-Token` header on every state-changing request. The server
validates the two match. Because the attacker can't read either the
session cookie or the csrf cookie cross-origin, the double-submit is
sufficient.

### Cookie layout

| Cookie | Contents | HttpOnly | Secure | SameSite | Lifetime |
|--------|----------|----------|--------|----------|----------|
| `aac_session` | tenant-user session token | yes | yes (prod) | Lax | matches `session_lifetime_hours` |
| `aac_admin` | operator admin token | yes | yes (prod) | Lax | matches admin token TTL |
| `aac_csrf` | random CSRF token | **no** (frontend must read it) | yes (prod) | Lax | per session |

`Secure` is off in local dev (`debug: True`) so cookies work over
plain HTTP. The auth module sets the flag from settings, not from a
literal.

### Why double-submit and not synchronizer token

Synchronizer token (server holds a per-session CSRF value, frontend
fetches it from `/csrf-token`, server compares against the value on
disk) is the textbook pattern but requires server-side storage.
Double-submit (server compares the cookie value against the header
value; both came from the client; an attacker can't set the cookie
on the user's behalf cross-origin) is stateless and good enough for
our threat model. Recommended by OWASP for SPAs.

The csrf cookie value is per-session, regenerated on login, cleared
on logout. The token is opaque to the frontend — it just copies
cookie → header.

## Implementation outline

### Backend

```
api/src/core/cookies.py       (new)
    set_session_cookie(response, token, settings) -> None
    clear_session_cookie(response) -> None
    set_admin_cookie(response, token, settings) -> None
    clear_admin_cookie(response) -> None
    set_csrf_cookie(response, settings) -> str
    require_csrf(request) -> None    # dependency factory

api/src/core/sessions.py
    require_tenant_user(...)         # accept token from cookie OR header
                                     # during the transition phase
api/src/core/admin_auth.py           (new — extract from current logic)
    require_admin(...)               # cookie OR header

api/main.py
    settings.cookie_secure: bool     # derived from `not debug`
    settings.cookie_samesite: str    # default "lax"
```

The `Authorization: Bearer` path is preserved during the migration
window (see § Migration). Both paths converge on the same
`require_tenant_user` / `require_admin` dependencies; the dependency
reads from whichever source has a value.

### Login flow change

```
POST /api/portal/v1/auth/login
    body: { tenant_id, email, password }
    --- successful response:
    Set-Cookie: aac_session=<token>; HttpOnly; Secure; SameSite=Lax
    Set-Cookie: aac_csrf=<random>; Secure; SameSite=Lax
    body: { mfa_required, mfa_verified, expires_at }
        # NOTE: no session_token in body — browsers don't need it
```

The body's `session_token` field is removed in the cookie world.
During the migration phase it stays so non-browser clients (CLI / curl
testers) can still pull it from the response.

### CSRF middleware

```
api/src/core/csrf.py    (new)
    require_csrf as a FastAPI Depends factory.
    Applied via dependency on every POST / PATCH / DELETE endpoint
    that uses cookie auth.
```

`GET` is exempt — read-only methods aren't CSRF targets.

The dependency reads `aac_csrf` from the cookie and `X-CSRF-Token`
from the header, asserts they're equal and non-empty. Mismatch → 403.

### Frontend

```
frontend/src/lib/auth.ts
    - drop localStorage reads / writes
    - readCsrfFromCookie(): reads aac_csrf cookie value
frontend/src/lib/api.ts
    - axios `withCredentials: true` so cookies travel
    - request interceptor: attach X-CSRF-Token from cookie on
      POST / PATCH / DELETE
frontend/src/App.tsx
    - RequirePortalUser / RequireAdmin check via a /me call
      (server returns 401 if no valid cookie) rather than reading
      localStorage
```

The `getUserSession` / `getAdminToken` / `clearUserSession`
helpers go away. Instead, a small `useSession` hook calls `/me` on
mount and caches the result; logout calls the existing logout endpoint
and lets the server clear the cookies.

## Migration

The trick: SPAs and non-browser clients use the same endpoints. We
can't flip the auth mode hard. Three releases:

| Release | Backend | Frontend | Reversible? |
|---------|---------|----------|-------------|
| N | Login endpoints set BOTH cookie AND return `session_token` in body. `require_tenant_user` accepts cookie OR `Authorization` header. CSRF dependency exists but is NOT applied yet. | Still uses localStorage path; ignores the cookie. | Yes — disable cookie setting |
| N+1 | Apply CSRF dependency to state-changing endpoints. | Switch to cookie path; clear localStorage on first load; honor CSRF. | Reversible per-PR but realistically forward-only once the frontend ships |
| N+2 | Drop the `session_token` from the response body. Drop the Authorization-header path. | (nothing — already on cookies) | No |

Phase N is risk-free. Phase N+1 is the real switch — needs a coordinated
release. Phase N+2 is cleanup.

## Open questions

1. **Cross-origin posture.** Today the frontend is served by nginx on
   port 3000 and the API is `api:8000` inside the compose network. After
   PR #37 the API isn't published; the SPA always sees the API at the
   same origin via `/api/`. So we're same-origin and `SameSite=Lax` is
   fine. Confirm there's no future plan to split origins (e.g. CDN-hosted
   SPA + separate API host).
2. **Admin token UX.** The operator admin token is currently shown by
   the login screen for copy-paste. With cookies, the operator never
   *sees* the token. That's a UX change. Is the existing
   `setAdminToken(token)` flow used outside the SPA (CLI scripts, ops
   tooling)? If yes, we keep the bearer path for those callers; if no,
   we can drop it.
3. **CLI / integration tests.** httpx + pytest can drive cookies fine
   (`AsyncClient` supports them), so existing tests adapt. The 23-tenant
   integration test in `test_tenant_users_integration.py` uses the
   admin token via header — we either keep header-path for admin during
   transition, or switch the test to login-and-use-cookie.
4. **Logout-everywhere semantics.** Today "sign out of all devices"
   revokes every session row server-side; the browser clears
   localStorage. With cookies, clearing one browser's cookie doesn't
   touch any other browser. The server-side revocation already handles
   the security-critical part — but the user-facing message should
   probably change.
5. **Cookie name prefix.** `__Host-aac_session` would add transport
   security (rejects on HTTP, no `Domain=` attribute, must be `/`).
   Recommendation: use `__Host-` prefix in production, plain name in
   dev. Trade-off: tooling that introspects cookies sometimes hides
   `__Host-` cookies.

## Out of scope

- **Tenant token secret** (M2M bridge auth) stays as bearer. Bridges
  are not browser clients; cookies don't apply.
- **Per-request bearer for the LLM / OPA proxy paths** — those are
  internal server-to-server; cookies aren't involved.
- **SAML / OIDC for SSO.** A future PR. Cookie-based session is a
  prerequisite, but the SSO design is separate.

## Acceptance criteria for the implementation PRs

- Backend supports BOTH header and cookie paths through phase N+1 (one
  test exercises each).
- CSRF protection covers every state-changing endpoint; one test
  asserts a mismatched CSRF returns 403.
- Frontend has zero `localStorage.setItem(...token...)` call sites
  after phase N+1.
- `useSession` / `useAdmin` hooks centralize the auth check (no
  per-page re-implementation).
- A new doc — `docs/customer_portal_guide.md` — explains the
  cookie-based session model in customer terms (replaces references
  to "session token in the response body").

## Implementation effort

- Phase N (backend cookie support, frontend untouched): 1 day
- Phase N+1 (frontend switch + CSRF wiring + tests): 1.5 days
- Phase N+2 (cleanup): 0.5 day

Roughly 3 engineering days total. The risk is concentrated in
phase N+1 — every page that calls the API needs `withCredentials`
and CSRF.
