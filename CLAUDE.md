# AAC_Customer_Portal — CLAUDE.md

## Purpose

The Customer Portal is the **customer-facing self-service surface** for AAC. Where the `compliance` repo is the operator's orchestrator (assessments, playbooks, EDA rulebooks), this is where customers see their compliance state, upload their own policies, fork from the standard library, request remediation, and download evidence.

Three reader types:

- **Tenant users** — customer end-users; login + MFA, see their tenant's policies/bundles/baselines
- **Tenant admins** — same surface + tenant-admin operations
- **Operators (us)** — bearer-token admin surface over all tenants (`/api/admin/v1/*`), plus the CVE/feeds/classification system

## Session startup checklist

At the start of every session in this repo:

1. **Confirm the environment**. The user will say it; if not stated, ask. Portal is currently lab-only but will go to customer environments. Never assume.
2. **Check all 3 repo cleanliness** — see "Cross-repo state check" in `~/.claude/CLAUDE.md`. 0 open PRs and 0 unsynced branches per repo is the green state.
3. **Migrations are append-only** — never edit a numbered migration that's been merged; always add a new one (`0NN_<name>.sql`)
4. **Read memory** — `~/.claude/projects/.../memory/MEMORY.md` for in-flight workstreams

## Environment isolation (HARD RULE)

Portal deploys to three distinct environments. Each has its own DB instance, OPA endpoints, AAP target. The same code runs in each; the difference is purely configuration via env vars (`api/src/core/config.py`'s Settings).

| Env | Portal hostname | Compliance DB | Portal DB | OPA URLs | AAP URL |
|---|---|---|---|---|---|
| **Lab** | lab portal | `192.168.4.62` | lab | lab 8181/8182/8183 | `https://192.168.4.62` |
| **Demo** | per-RHPDS-cluster | per-cluster | per-cluster | per-cluster | per-cluster |
| **Customer** | customer-provided | customer | customer | customer | customer |

**Never let lab IPs (`192.168.4.62`, `192.168.4.26`) leak into customer or demo env files, code defaults, or docs.** `core/config.py` defaults to `localhost` for this exact reason — if the operator forgets to override, the failure is loud (can't connect), not silent (connects to the wrong place).

When you produce a customer install runbook, replace every IP with placeholders: `<customer-portal-host>`, `<customer-aap-host>`.

## Stack

| Layer | Technology |
|---|---|
| API | FastAPI 0.111, Pydantic 2.7, asyncpg 0.29, Python 3.11 |
| Frontend | React 18, Vite 5, PatternFly, axios, Vitest |
| Containers | **podman** (never docker), `podman-compose` |
| DBs | Two: **`aac_portal`** (portal-owned, app user) + **`compliance`** (read-only via `compliance_reader`) |
| Auth | tenant_users + tenant_user_sessions (bearer) + TOTP MFA |
| Logs | asgi-correlation-id + JSON formatter; X-Request-ID end-to-end |
| Audit | `system_audit_log` table + `AuditMiddleware` — see `api/src/core/audit_middleware.py` |
| Rate limit | `limits` library via FastAPI Depends factory |

## Repository structure

```
api/
├── main.py                 FastAPI app, middleware stack, router registry
├── requirements.txt        Pinned (asgi-correlation-id, python-json-logger included)
├── migrations/             Numbered SQL (001…014_system_audit_log.sql)
├── scripts/                One-off ops scripts
├── src/
│   ├── core/
│   │   ├── config.py       Pydantic Settings — single source of env config
│   │   ├── database.py     compliance_reader pool (compliance DB)
│   │   ├── portal_db.py    aac_portal_app pool (portal-owned writes)
│   │   ├── sessions.py     require_tenant_user / require_tenant_user_mfa
│   │   ├── logging.py      configure_logging() — JSON or plain
│   │   ├── audit.py        record_audit() helper
│   │   ├── audit_middleware.py  AuditMiddleware
│   │   ├── rate_limit.py   per-route Depends factory
│   │   └── ...
│   ├── routers/            17+ routers (compliance, auth, me, me_mfa, baselines,
│   │                       bundles, classification, enrollments, feeds,
│   │                       policies, portal_feed, standard_library,
│   │                       tenant_users, tenants, remediation, reports, aap)
│   ├── models/             Pydantic response models
│   ├── feeds/              CVE feed ingestion + classification
│   └── policy_ingestion/   Path A (upload → IR → Rego) + Path B (standard library fork)
└── tests/                  Backend tests (unit + integration)

frontend/
├── package.json
├── package-lock.json       MUST stay in sync with package.json (npm ci uses it)
├── nginx.conf              CSP, X-Frame-Options, HSTS — DO NOT WEAKEN
├── vite.config.ts
├── vitest.config.ts
├── src/
│   ├── lib/api.ts          Axios clients: public, admin (bearer), tenant (bearer+X-Token-Id), user (session)
│   ├── lib/auth.ts         Session storage
│   ├── pages/              Portal pages + .test.tsx siblings
│   ├── components/
│   ├── types/              TS type definitions
│   └── test/               Vitest setup
└── dist/                   Build output (gitignored)

deploy/
└── podman/
    ├── docker-compose.yml  Named for portability — we use `podman-compose`
    ├── env.example         Required env vars
    └── Containerfile.api / Containerfile.frontend

docs/                       Design docs (Phases 5/6/7, SoW, runbooks, security roadmap)
.github/workflows/          api-tests.yml + frontend-tests.yml + codeql.yml
```

## Skill: FastAPI + dependency-injection

Every protected endpoint takes an auth dependency:

```python
from typing import Annotated
from fastapi import Depends
from ..core.sessions import require_tenant_user, require_tenant_user_mfa

@router.get("/something")
async def list_something(
    user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: asyncpg.Pool = Depends(get_portal_pool),
):
    ...
```

- `require_tenant_user` — any logged-in tenant user (reads)
- `require_tenant_user_mfa` — MFA-verified session required (writes, publish, infrastructure mutation)
- Router-level gating: `dependencies=[Depends(require_tenant_user)]` on the `APIRouter(...)` constructor

For tests: override via `app.dependency_overrides[require_tenant_user] = lambda: fake_user`. Don't mint real bearer tokens in tests.

## Skill: tenant-scoped queries

Every query against `aac_portal` that returns tenant-owned data MUST filter by `tenant_id`:

```python
rows = await pool.fetch(
    "SELECT * FROM customer_policies WHERE tenant_id = $1 AND status = 'published'",
    user["tenant_id"],
)
```

Forgetting this is the cardinal multi-tenant bug. Schema-level FKs enforce `tenant_id` on every tenant-owned table; if you find yourself writing a query without one, stop and check.

Cross-tenant data (CVE feeds, standard library, buckets) is on its own surface (`/admin/v1/*`) gated by `PORTAL_ADMIN_TOKEN`, not tenant auth.

## Skill: tenant-user auth (cookies + CSRF, PR #67–69)

The tenant-user surface (`/api/portal/v1/me/*`, `/api/portal/v1/auth/*`) uses HttpOnly cookies, not Authorization bearer:

- **Login** (`POST /api/portal/v1/auth/login`) sets `__Host-aac_session` (HttpOnly, prod) / `aac_session` (dev) and `__Host-aac_csrf` (non-HttpOnly) cookies. Body returns `session_token: null` by default; CLI clients opt in via `X-Portal-Client: cli` header and get the bearer token in the body.
- **Subsequent requests**: browser sends cookies automatically via `withCredentials: true`. State-changing methods (POST/PATCH/DELETE/PUT) require `X-CSRF-Token` header matching the `aac_csrf` cookie — enforced by `CsrfMiddleware` (`api/src/core/csrf.py`). The middleware skips enforcement when no cookie is present (bearer/CLI path).
- **`require_tenant_user`** dependency reads from cookie first, falls back to bearer. Cookie wins.

Operator admin (`/api/admin/v1/*`) still uses `PORTAL_ADMIN_TOKEN` bearer — no admin login flow exists yet (see design doc Open Question 2). Don't migrate it to cookies without first designing the admin login UX.

Frontend cookie reader: `frontend/src/lib/auth.ts:readCsrfCookie()`. CSRF interceptor: `frontend/src/lib/api.ts:csrfRequestInterceptor` (axios, applied to `userApi`).

## Skill: audit logging

Every mutation (POST/PUT/PATCH/DELETE) and every 4xx/5xx response auto-logs to `system_audit_log` via the middleware. Routers can attach richer context:

```python
@router.patch("/items/{item_id}")
async def update(item_id: str, request: Request):
    # Will be picked up by AuditMiddleware on the way out:
    request.state.audit_resource = ("remediation_item", item_id)
    request.state.audit_extra = {"old_status": ..., "new_status": ...}
    ...
```

DB failures during audit insert are swallowed at WARNING level — they never break the response. That's by design (better to miss the occasional row than to 500 the actual operation).

### Immutability triggers (migrations 017 + 018)

`policy_audit_log` and `baseline_snapshots` are storage-layer append-only. `BEFORE UPDATE` / `BEFORE DELETE` triggers `RAISE EXCEPTION` on any direct mutation. Two narrow exceptions:

1. **FK SET NULL cascade**: an UPDATE that ONLY nulls out `tenant_user_id`, `customer_policy_id`, or `captured_by_user_id` is allowed (needed so the existing "(user removed)" UX path keeps working).
2. **Legal-hold toggle**: setting / clearing `legal_hold_reason` is the one always-allowed column change. While `legal_hold_reason IS NOT NULL`, the row is absolutely frozen — even FK cascade is blocked.

**Consequence:** hard `DELETE FROM tenants` is now blocked when the tenant has audit history. Use soft-delete (`UPDATE tenants SET status='deleted'`). The break-glass "tenant purge" path is documented in `docs/runbooks/tenant_purge.md`.

**Don't write `UPDATE policy_audit_log SET ...` or `DELETE FROM baseline_snapshots ...` from new code.** If you think you need to, you almost certainly want either a new INSERT (append, don't mutate) or a legal-hold operation via `/api/admin/v1/legal-holds`.

## Skill: migrations

- SQL, numbered (`014_<name>.sql`), wrapped in `BEGIN; ... COMMIT;`
- Apply in numeric order on every fresh env
- **Once merged to main, NEVER edit a migration** — add a new one
- Schema changes that need backfill: ship the migration + a one-off Python script in `api/scripts/` that runs once

## Skill: testing

Three layers:

```bash
cd api && pytest tests/                                        # unit + light integration
cd api && pytest tests/test_*_integration.py                   # needs real PG (testcontainers)
cd frontend && npm test                                        # Vitest
```

Patterns:

- Auth bypass: `app.dependency_overrides[require_tenant_user] = lambda: fake_user`
- Pool stub: `app.dependency_overrides[get_portal_pool] = lambda: None` (auth rejects before pool use)
- Real-DB integration: `pg_pool` fixture from `tests/db_fixtures.py`
- Audit: stub `record_audit` via `monkeypatch.setattr(audit_mod, "record_audit", fake)`

## Skill: routes the frontend calls

Frontend → backend route inventory lives in `frontend/src/lib/api.ts`. When you add a backend endpoint:

1. Implement the router (`api/src/routers/<name>.py`)
2. Register it in `api/main.py`
3. Add the TS type in `frontend/src/types/`
4. Add the call in `frontend/src/lib/api.ts`
5. Pin contract with a unit test on both sides

Stub routes that aren't ready yet (e.g. `/remediation`, `/reports/download`, `/aap/launch`) return 501 with structured detail — keeps the contract honest while flagging the gap. See PR #42 for the pattern.

## Container runtime

- **podman only** — never docker
- `podman-compose -f deploy/podman/docker-compose.yml up`
- Inside-container references: `host.containers.internal` for host
- Frontend `npm ci` requires `package-lock.json` in sync — if you bump frontend deps, commit the regenerated lock (see PR #38 for the issue this caused)

## RHEL convention

- All Containerfiles use `registry.access.redhat.com/ubi9` (or `ubi9-minimal`)
- No Debian/Ubuntu base images
- When testing locally on macOS, the deploy artifacts still need to be RHEL-compatible — verify before merging

## Generated documents

Same convention as the other repos:

1. Write canonical version to `docs/`
2. Save 2 copies to `~/Downloads/`:
   - `~/Downloads/<filename>.md` — current
   - `~/Downloads/<filename>-YYYY-MM-DD.md` — dated snapshot
3. Customer-facing artifacts: include Markdown AND a styled PDF/DOCX in the Downloads pair
4. Version: `**Version:** v1.0` near the top; bump on revision

## Git workflow

- **Never push directly to main** — PRs only
- **Branch protection (MainBranch ruleset)** applies to `~ALL` branches and requires:
  - CodeQL (security scanning) — `.github/workflows/codeql.yml`
  - Code quality
  - Copilot code review
  - No fast-forward; no force-update; no deletion
- **`Approved-By:` trailer required** for protected paths (`.github/workflows/`, `api/migrations/`, `deploy/`)
- **CI gates** (all must pass):
  - `pytest` — backend tests (`api-tests.yml`)
  - `vitest + tsc + vite build` — frontend (`frontend-tests.yml`)
  - `CodeQL` + `Analyze (python)` + `Analyze (javascript-typescript)` — `codeql.yml`
  - `bandit` — Python SAST, HIGH severity gate (`bandit.yml`)
  - `npm audit` — JS dependency advisories, HIGH severity gate (`npm-audit.yml`)
  - `SBOM (api)` + `SBOM (frontend)` — SPDX generation (`sbom.yml`)

### Action provenance (PR #77)

Every `uses:` reference in `.github/workflows/*.yml` is pinned to a **full commit SHA** with a `# v<major>` trailing comment. Never use moving major-version tags. When introducing a new action:

```yaml
- name: ...
  uses: owner/action@<40-char-sha>  # v<major>
```

Look up SHAs with `gh api repos/<owner>/<action>/commits/v<major> --jq '.sha'`. Dependabot (`.github/dependabot.yml`) opens one grouped PR per week for minor + patch bumps; major upgrades are hand-crafted (research migration, look up SHA, write the comment, handle any workflow-syntax changes).

### Bypass workflow

The MainBranch ruleset rejects pushes / merges when CodeQL has open `high_or_higher` alerts on the diff — even when this PR is the one fixing them. The recurring pattern is:

```bash
# add admin bypass
gh api -X PUT repos/ynotbhatc/AAC_Customer_Portal/rulesets/17373111 \
  --input <(echo '{"bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}]}') \
  --jq '.bypass_actors'

# admin-merge
gh pr merge <PR> --squash --delete-branch --admin

# clear bypass (always restore!)
gh api -X PUT repos/ynotbhatc/AAC_Customer_Portal/rulesets/17373111 \
  --input <(echo '{"bypass_actors":[]}') \
  --jq '.bypass_actors'
```

`actor_id=5` is the `RepositoryRole=admin` ID, not a user ID. Don't substitute a user ID. Always clear the bypass after merging.

## Operator runbooks

Live in `docs/runbooks/`:

- **`tenant_purge.md`** — hard-deleting a tenant (GDPR right-to-erasure, end-of-contract). Requires DROP TRIGGER → audit → DELETE → CREATE TRIGGER dance because of migration 017's immutability triggers.
- **`legal_hold.md`** — applying / releasing legal hold. Primary path is the admin API (`POST/DELETE/GET /api/admin/v1/legal-holds`); direct SQL is documented as break-glass.

Add new runbooks when shipping a feature that requires manual operator intervention OR when migration changes break a previously-routine operation.

## Working with contributors from other teams

Architecture and repo structure are ours to define. Outside contributors:

- Fork into branches, never main
- PRs must follow the patterns documented here (auth dependency, tenant-scoped queries, migration numbering, audit middleware integration)
- For any new endpoint OR new migration: open a discussion first — schema and routing decisions stay with us
- We are the only reviewers for `api/migrations/`, `api/src/core/`, `.github/workflows/`, and `deploy/`
- For UX/page work, design docs in `docs/` are the source of truth — implementation follows the design

## Claude Code Skills

Project-level skills live in `.claude/skills/<name>/SKILL.md` and are committed to the repo.

### Current skills

| Skill | Description |
|-------|-------------|
| `/api-health-deep` | Cascading health check — nginx → API `/health` → both PG pools → all 3 OPA endpoints; show which layer is degraded |
| `/nginx-test-headers <url>` | Curl + show every response header (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy); verify the security headers in `frontend/nginx.conf` are actually being applied |
| `/git-migration-numbering` | Pre-commit check: warn if a migration file isn't strictly N+1 of the prior numbered migration, and if any committed migration is being edited (must add new file instead) |

### Gateway-tech skill catalog (proposed)

These wrap nginx, FastAPI, auth, rate-limit, and OPA gateway operations. Worth building when the operator workflow needs them.

| Proposed skill | What it does |
|---|---|
| `/nginx-reload` | Validate config (`nginx -t`), then reload (`nginx -s reload`) — fail-fast that won't drop traffic on a bad config |
| `/nginx-csp-check` | Test CSP against the frontend dist — fetch index.html, parse script/style/link, verify each is allowed by the policy |
| `/nginx-rate-limit-test <endpoint>` | Hammer an endpoint at the configured rate-limit threshold and confirm 429 fires |
| `/api-openapi-dump` | Hit `/openapi.json`, summarize every route (method, path, auth required, body shape) |
| `/api-route-map` | Show `frontend/src/lib/api.ts` calls vs `api/src/routers/*` registered paths; flag any frontend call to a missing backend route |
| `/api-test-cors <origin>` | OPTIONS preflight from a given Origin; verify CORS headers |
| `/portal-login <tenant_id> <email>` | Run the full login flow (POST /portal/v1/auth/login → store session → call /me) |
| `/portal-session-info` | Decode the current stored session: tenant, user, role, MFA state, expiry |
| `/portal-mfa-status` | For the current session, show which MFA factors are enrolled + whether `mfa_verified` is set |
| `/portal-token-revoke <session_id>` | Revoke a session via the admin surface |
| `/rate-limit-status <key>` | Read current counter/window from rate-limit storage |
| `/rate-limit-reset <key>` | Clear a single user's rate-limit counter (incident-response use) |
| `/opa-build-bundle <profile>` | Run validate_demo_bundle.py against a customer profile end-to-end |
| `/opa-publish-bundle <tenant>` | Trigger a customer-specific bundle publish via `/me/bundles/build` |
| `/tls-cert-check <host>` | openssl-fetch the cert, show subject + issuer + days-until-expiry |
| `/webhook-test-bridge <endpoint>` | Send a synthetic payload to one of the portal's bridge endpoints (CVE feed, GitHub mirror, etc.) |

### Git skill catalog

Portal-specific git operations have patterns worth automating: migration numbering, ruleset bypass workflow, npm lock-file sync.

| Proposed skill | What it does |
|---|---|
| `/git-migration-numbering` | (Shipped) Pre-commit check for migration file numbering |
| `/git-npm-lock-check` | Verify `frontend/package.json` and `frontend/package-lock.json` are in sync; emit the `npm install` command needed if not |
| `/git-ruleset-bypass-workflow` | Walk through the established pattern: add admin to MainBranch bypass_actors → merge → clear bypass. For the operator who's done it once but needs the exact commands again |
| `/git-pr-status [pr_number]` | Same as the compliance-repo skill: full PR state in one shot |
| `/git-protected-paths-check` | Same as compliance: warn before committing to `.github/workflows/`, `api/migrations/`, `deploy/` |
| `/git-find-pr-for-commit <sha>` | Given a commit SHA on main, find which PR introduced it |

### Skills authoring rules

1. **Always resolve file paths via `git rev-parse --show-toplevel`** — skills can be invoked from any working directory
2. **Use `$1`/`$2` for positional arguments**, not `$0`
3. **Validate HTTP status codes explicitly** with `-w "%{http_code}" -o /dev/null`
4. **Keep descriptions specific and front-loaded** — only the description is in context; the body is loaded on invocation
5. **Use `allowed-tools` frontmatter** to pre-approve Bash commands

## Documentation pointers

- **FastAPI**: https://fastapi.tiangolo.com/
- **Pydantic**: https://docs.pydantic.dev/
- **asyncpg**: https://magicstack.github.io/asyncpg/current/
- **PatternFly**: https://www.patternfly.org/
- **React**: https://react.dev/
- **Vitest**: https://vitest.dev/
- **asgi-correlation-id**: https://github.com/snok/asgi-correlation-id
- **python-json-logger**: https://github.com/madzak/python-json-logger
- **OPA**: https://www.openpolicyagent.org/docs/
- **Compliance repo (peer)**: https://github.com/ynotbhatc/compliance
- **Policy library (used by Path B fork)**: https://github.com/ynotbhatc/rego_policy_libraries
