# Design — HttpOnly Cookies + CSRF for Browser Auth

**Status:** draft for review — implementation gated on the answers
to the Open Questions section.

**Principle:** This is auth for a security product. Browser-side
credential storage has to be **right** the first time — no
"localStorage for now, cookies later." No commercial product
dependency, pure engineering work; we can ship the production
design at customer-1 grade today.

## Problem

Three browser-facing tokens currently live in `localStorage`
(`frontend/src/lib/auth.ts:3-4, 33-35, 46-69`):

- Operator **admin token** — gates `/api/admin/v1/...` endpoints
- Tenant **user session token** — gates `/api/portal/v1/me/...`
- Tenant **token secret** — operator-issued M2M secret; shown once
  in the UI and copy-pasted into the AAC bridge config

`localStorage` is readable by any JavaScript that runs on the page.
One XSS — bypassed CSP, an unsanitized field, a compromised npm
dependency — exfiltrates every token stored there. For a security
product, the localStorage path is not acceptable.

## Recommendation

Move both browser-resident tokens (admin + user session) to
**HttpOnly, Secure, SameSite=Lax cookies** so JS can't read them.
Add a **double-submit CSRF token** for state-changing requests:
the server issues a non-HttpOnly `aac_csrf` cookie at login, the
frontend reads it and echoes it back via `X-CSRF-Token` on POST /
PATCH / DELETE, the server validates the two match.

The tenant **token secret** (M2M auth between the AAC bridge and
the portal) **stays as bearer** — bridges are not browser clients;
cookies don't apply.

### Cookie layout

| Cookie | Contents | HttpOnly | Secure | SameSite | Lifetime |
|--------|----------|----------|--------|----------|----------|
| `__Host-aac_session` | tenant-user session token | yes | yes (prod) | Lax | matches `session_lifetime_hours` |
| `__Host-aac_admin` | operator admin token | yes | yes (prod) | Lax | matches admin token TTL |
| `__Host-aac_csrf` | random CSRF token | **no** (frontend must read) | yes (prod) | Lax | per session |

`__Host-` prefix rejects cookies on HTTP, requires `Path=/`, and
forbids `Domain=` — the strictest transport guarantees available
in cookie-land. Dev uses bare names (HTTP works); production uses
the prefixed forms.

### Why double-submit and not synchronizer token

Synchronizer token (server holds a per-session CSRF value, frontend
fetches it from `/csrf-token`, server compares against the value
on disk) is textbook but requires server-side storage. Double-submit
is stateless and equivalently secure for our threat model: an
attacker can't both set the cookie on the user's behalf AND read
the cookie value cross-origin. OWASP-recommended for SPAs.

## Implementation outline

### Backend

```
api/src/core/cookies.py    (new)
    set_session_cookie(response, token, settings) -> None
    clear_session_cookie(response) -> None
    set_admin_cookie(response, token, settings) -> None
    clear_admin_cookie(response) -> None
    set_csrf_cookie(response, settings) -> str
    require_csrf(request) -> None    # Depends factory

api/src/core/sessions.py
    require_tenant_user(...)    # cookie OR Authorization header
                                # during transition window

api/src/core/admin_auth.py    (new — extract current logic)
    require_admin(...)          # cookie OR header
```

The `Authorization: Bearer` path is preserved during the migration
window. Both paths converge on the same `require_tenant_user` /
`require_admin` dependencies; the dependency reads from whichever
source has a value.

### Login flow change

```
POST /api/portal/v1/auth/login
    body: { tenant_id, email, password }
    --- successful response:
    Set-Cookie: __Host-aac_session=<token>; HttpOnly; Secure; SameSite=Lax
    Set-Cookie: __Host-aac_csrf=<random>;  Secure; SameSite=Lax
    body: { mfa_required, mfa_verified, expires_at }
        # NOTE: no session_token in body for browser callers.
        # During the transition window, a `X-Portal-Client: cli`
        # header opts back into the body-token path for non-browser
        # callers (integration tests, scripts).
```

### CSRF middleware

```
api/src/core/csrf.py    (new)
    require_csrf — Depends factory.
    Applied via dependency on every POST / PATCH / DELETE endpoint
    that uses cookie auth.
```

GET / HEAD are exempt — read-only methods aren't CSRF targets.

Mismatch → 403 with `detail: "csrf mismatch"`.

### Frontend

```
frontend/src/lib/auth.ts
    - Drop localStorage reads / writes
    - readCsrfFromCookie(): reads __Host-aac_csrf

frontend/src/lib/api.ts
    - axios: withCredentials: true
    - request interceptor: attach X-CSRF-Token from cookie on
      POST / PATCH / DELETE

frontend/src/App.tsx
    - RequirePortalUser / RequireAdmin gate on a /me call
      (server returns 401 if cookie missing or invalid)
      rather than reading localStorage
```

`getUserSession` / `getAdminToken` / `clearUserSession` go away.
Replaced by a small `useSession` hook that calls `/me` on mount
and caches; logout calls the existing logout endpoint and lets
the server clear the cookies.

### Migration

Three releases — the SPA and non-browser clients use the same
endpoints, so we can't flip auth mode hard.

| Release | Backend | Frontend | Reversible? |
|---------|---------|----------|-------------|
| N | Login endpoints set cookies AND return `session_token` in body. `require_tenant_user` accepts cookie OR header. CSRF dependency exists but is NOT yet applied. | Still uses localStorage; ignores the cookie. | Yes — disable cookie setting |
| N+1 | Apply CSRF dependency to state-changing endpoints. | Switch to cookie path; clear localStorage on first load; honor CSRF. | Reversible per-PR; realistically forward-only once frontend ships |
| N+2 | Drop `session_token` from response body for browser callers (keep the `X-Portal-Client: cli` opt-in for CLI). Drop the Authorization-header path for browser flows. | (nothing — already on cookies) | No |

Phase N is risk-free. Phase N+1 is the real switch — needs a
coordinated release. Phase N+2 is the cleanup that locks in the
new world.

### AAC bridge interaction

This work doesn't change the bridge auth path:
- The bridge uses the tenant **token secret** as a bearer token,
  not a cookie.
- The tenant token secret stays in the API as a bearer-auth path.
- The cookie work covers only the operator console SPA and the
  tenant portal SPA — both browser-based.

## Open questions

1. **Cross-origin posture.** Today the SPA is served by nginx on
   port 3000 and the API is `api:8000` inside the compose network;
   PR #37 unpublishes 8000 so the SPA always sees the API at the
   same origin via `/api/`. Same-origin → `SameSite=Lax` is fine.
   **Are we sure there's no plan to ever serve the SPA from a CDN
   on a different origin?** If yes, we revisit `SameSite=None` and
   the CSRF strategy.
2. **Admin token UX trade-off.** Today the operator console shows
   the admin token after login so it can be copy-pasted into CLI /
   ops scripts. With cookies, the operator never sees the token.
   **Is the admin token used outside the browser today?** If yes,
   we need to either: (a) ship a separate "issue CLI token" admin
   action that returns the token in the response body, or (b) keep
   the bearer path indefinitely for ops while cookies handle the
   SPA. **Recommendation: (a), with the CLI token having a
   shorter TTL than the cookie path.**
3. **CLI / integration tests.** httpx + pytest handle cookies fine
   (`AsyncClient` supports them). The existing
   `test_tenant_users_integration.py` uses the admin token via
   header. **Recommendation: keep the header path during the
   transition; convert the test to cookie path in phase N+2.**
4. **Logout-everywhere semantics.** Today "sign out of all
   devices" revokes every session row server-side; the browser
   clears localStorage. With cookies, clearing one browser's
   cookie doesn't touch any other. The server-side session
   revocation already handles the security-critical part — but
   the UI message should change from "Sign out of all devices"
   to "Revoke all active sessions" so the model is honest.

## Out of scope

- **Tenant token secret** (M2M bridge auth) stays as bearer.
- **Per-request bearer for the LLM / OPA proxy paths** — internal
  server-to-server; cookies don't apply.
- **SAML / OIDC for SSO.** A future PR. Cookie-based session is a
  prerequisite, but the SSO design is separate.

## Acceptance criteria for the implementation PRs

- Backend supports BOTH header and cookie paths through phase N+1
  (one test exercises each).
- CSRF protection covers every state-changing endpoint; one test
  asserts a mismatched CSRF returns 403.
- Frontend has zero `localStorage.setItem(...token...)` call sites
  after phase N+1.
- `useSession` / `useAdmin` hooks centralize the auth check (no
  per-page re-implementation).
- `docs/customer_portal_guide.md` is updated to describe the
  cookie-based session model in customer terms (replaces
  references to "session token in the response body").

## Implementation effort

- Phase N (backend cookie support, frontend untouched): 1 day
- Phase N+1 (frontend switch + CSRF wiring + tests): 1.5 days
- Phase N+2 (cleanup): 0.5 day

Roughly 3 engineering days total. Risk concentrated in phase N+1
— every page that calls the API needs `withCredentials` and CSRF.
