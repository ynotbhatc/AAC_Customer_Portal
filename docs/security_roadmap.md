# Security Roadmap

The portal is a security product. The architecture has to be **right**
the first time — no hostile-by-default patterns shipped under the
assumption "we'll fix it later." But "right" doesn't mean "every
backend is production-grade on day one." The architecture stays
right; the backends graduate from OSS / dev tier to production tier
on a clear schedule.

This document is the **open list** — things we are shipping at a
lower tier today that MUST be addressed before specific milestones.
Every entry has a clear trigger that says when it becomes blocking.

## Conventions

- 🟢 **Production grade.** Acceptable for paying customers.
- 🟡 **OSS / dev tier.** Acceptable now; carries a documented upgrade
  path. Must be replaced before the trigger.
- 🔴 **Blocker.** Must be done before the trigger; not yet started.

## Triggers

In order of how close they are:

- **First customer onboard.** Paying customer signs an order; their
  data lands in our database.
- **First SOC 2 audit.** External auditor reviewing controls.
- **First FedRAMP / regulated tenant.** GovCloud or
  defense-vertical customer.

## Open items

### Credential storage

| Item | Today | Trigger | Production target |
|------|-------|---------|-------------------|
| TOTP secrets at rest | 🟡 `LocalSealedKeyProvider` (KEK sealed by `SECRET_KEY`, file on disk) | First customer onboard | 🟢 OpenBao Transit |
| Tenant token secrets at rest | 🟡 `LocalSealedKeyProvider` | First customer onboard | 🟢 OpenBao Transit |
| KEK rotation | 🔴 Manual / not scheduled | First SOC 2 audit | 🟢 Automated 90-day rotation |
| KMS-unavailable behavior | 🔴 Not yet defined | First customer onboard | 🟢 Fail closed; documented runbook |

**Design:** `docs/design_secret_encryption.md`

The crucial principle: **the architecture lands now** (envelope
encryption, per-secret DEK, pluggable KEY interface). What changes at
the trigger is the *backend* — flip `KEK_PROVIDER` from `local_sealed`
to `openbao`. The call sites and database schema don't move.

### Browser auth

| Item | Today | Trigger | Production target |
|------|-------|---------|-------------------|
| Tenant-user tokens in cookies | 🟢 Phase N+1: SPA reads from HttpOnly `__Host-aac_session` (prod) / `aac_session` (dev) cookie via `withCredentials`. No copy in JS. RequirePortalUser gates on `/me` probe. Phase N+2: `session_token` is null in login response body for browser callers (CLI opts in via `X-Portal-Client: cli`). | done | done (browser); operator admin still bearer-only (no admin login flow) |
| CSRF protection on state-changing endpoints | 🟢 Phase N+1: `CsrfMiddleware` enforces double-submit on POST/PATCH/DELETE/PUT when the `aac_csrf` cookie is present. Frontend `csrfRequestInterceptor` echoes the cookie via `X-CSRF-Token`. Bearer-only requests (no cookie) pass through. | done | done |
| Reset token in URL query param | 🟢 URL `?token=` stripped on mount via `history.replaceState`; input no longer pre-fills from URL; only POST body carries the token | done | done |
| Logout-everywhere | 🟡 Works server-side; UI message is misleading | First SOC 2 audit | 🟢 UI rewording + audit-log entry |

**Design:** `docs/design_auth_cookies.md`

This is **all engineering effort, no commercial product dependency**.
We can ship the production design at customer-1 grade today; the
delay is sequencing, not capability.

### RBAC enforcement

| Item | Today | Trigger | Production target |
|------|-------|---------|-------------------|
| `require_role(...)` enforced on mutating endpoints | 🟢 Editor gates on all tenant-user writes: policies (×9), bundles, AAP launch, baselines, remediation (×5). `account_owner` retained on host-mappings. | done | done |
| Separation of duties — approve + publish | 🟡 Same user can approve a target and publish the policy | First SOC 2 audit | 🟢 Optional "4-eyes" policy per tenant |
| Permission audit reporting | 🟢 `GET /me/permissions` returns tenant roster + role-capability matrix; `PortalPermissionsPage.tsx` renders both, highlighting the caller's row | done | done |

**Note:** RBAC is a tactical fix — `Depends(require_role("editor"))`
on the right endpoints. No design doc needed; just an implementation
PR. The Copilot review (this thread) names the exact endpoints.

### Audit + immutability

| Item | Today | Trigger | Production target |
|------|-------|---------|-------------------|
| `policy_audit_log` immutability | 🟡 Schema says append-only; no DB-level trigger | First SOC 2 audit | 🟢 `BEFORE UPDATE / DELETE` deny triggers |
| `baseline_snapshots` immutability | 🟡 Same — no trigger | First SOC 2 audit | 🟢 Trigger |
| Retention / legal hold | 🔴 No policy | First SOC 2 audit | 🟢 Per-table TTL config + legal-hold flag |
| Audit action taxonomy | 🟢 Canonical enum in `api/src/core/audit_actions.py` mirrored in `frontend/src/types/auditActions.ts`; coverage tests on both sides | done | done |

### Supply chain

| Item | Today | Trigger | Production target |
|------|-------|---------|-------------------|
| OPA binary download | 🟢 SHA256-verified at build (`api/Containerfile`) | done | done |
| Standard library clone | 🟢 Pinned to commit SHA, init+fetch-by-ref (`api/Containerfile`) | done | done |
| Frontend SAST | 🔴 None | First SOC 2 audit | 🟢 `npm audit` in CI + `snyk` or equivalent |
| Backend SAST | 🟢 `bandit` runs in CI on every PR + weekly cron (`.github/workflows/bandit.yml`). Config in `api/pyproject.toml` skips B608 (asyncpg parameterization pattern; documented). Gate fails on HIGH severity; LOW + MEDIUM informational. Two inline `# nosec` markers cover the only HIGH false positives (jinja autoescape for Rego output; token-id product prefix). | done | done |
| Container image signing | 🔴 None | First FedRAMP tenant | 🟢 Cosign-signed images |
| SBOM generation | 🔴 None | First FedRAMP tenant | 🟢 Syft-generated SBOM per release |

### Network / runtime

| Item | Today | Trigger | Production target |
|------|-------|---------|-------------------|
| TLS verify off default for AAP | 🟢 Default `True` (PR #37) | done | done |
| Rate limiting on auth | 🟢 10/min login, 5/min reset-confirm (PR #39) | done | done |
| Structured logging + correlation IDs | 🟢 JSON via `python-json-logger`, X-Request-ID middleware (PR #40) | done | done |
| `/metrics` Prometheus endpoint | 🟢 `portal_http_requests_total{method,route,status_code}` counter + `portal_http_request_duration_seconds{method,route}` histogram. Route label uses the FastAPI template (cardinality-safe). Optional `X-Metrics-Token` gate via `METRICS_TOKEN` env. | done | done |
| Alerting on 5xx spike | 🔴 None — depends on log aggregator | First customer onboard | 🟢 Aggregator-side alerts; runbook |

### Database

| Item | Today | Trigger | Production target |
|------|-------|---------|-------------------|
| Per-table backups | 🟡 PostgreSQL native (depends on operator) | First customer onboard | 🟢 Point-in-time recovery + retention policy |
| At-rest encryption (disk-level) | 🟡 Depends on operator's storage | First SOC 2 audit | 🟢 Documented requirement: customer's storage must encrypt at rest |
| Connection pool sizing under load | 🔴 Defaults; not tuned | First customer onboard | 🟢 Load-tested with a real benchmark |

### AAC bridge integration

The portal bridges to on-site AAC. The trust chain has two sides:
the portal stores tenant token secrets; the bridge stores them in
its Ansible Vault. Each side is independently responsible for
protecting its half.

| Item | Today | Trigger | Production target |
|------|-------|---------|-------------------|
| Bridge token issuance audit | 🟢 Lands in `system_audit_log` via the audit middleware (POST → AUDITED_METHODS). The tenant router now tags `request.state.audit_resource` → `("tenant_token", token_id)` on create + revoke so auditors can filter by `resource_type='tenant_token'`. Same convention extended to `("tenant", id)` for create/update/delete tenant. | done | done |
| Bridge token revocation propagation | 🟢 Server-side revoke takes effect immediately on next bridge poll | done | done |
| Bridge identity attestation | 🔴 No attestation today; whoever holds the token IS the bridge | First FedRAMP tenant | 🟢 mTLS or signed-attestation on bridge identity |

## Maintenance

Update this file whenever:

- An item is implemented (move from 🟡/🔴 to 🟢; remove from open list).
- A new finding lands (Copilot review, threat model, customer ask).
- A trigger gets hit (escalate dependent items to 🔴; track in a
  PR if not already in flight).

Linked PRs at the top of every item's row so review history is one
click away.

## Reference

Design docs:
- `docs/design_secret_encryption.md`
- `docs/design_auth_cookies.md`

Recent hardening PRs (post-merge):
- #37 — config defaults, CORS lockdown, /health DB probe, nginx
  security headers
- #38 — frontend CI workflow + `__init__.py` files
- #39 — rate limiting on auth endpoints
- #40 — structured JSON logging + per-request correlation IDs
- #41 — these design docs + this roadmap
