# AAC Customer Portal — Reliability: SLIs, SLOs, Error Budgets

**Audience:** Internal planning — engineering, ops, product.
**Purpose:** Define measurable Service Level Indicators (SLIs), Service
Level Objectives (SLOs), and the error budgets they imply for every
surface of the Portal. Once these are in place, the change-management
policy gets teeth: a release that would consume more than the
remaining error budget is held back; a release that lands inside the
budget proceeds. Companion to `portal_saas_lens_assessment.md` (the
A1 reliability pillar gaps R1–R7 become measurable here).
**Drafted:** 2026-06-02
**Version:** v1.0

## Revision history

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-06-02 | Initial structure stub — surfaces enumerated. |
| v1.0 | 2026-06-02 | First full content pass — nine surfaces with SLIs/SLOs/error budgets per tier; composite SLA roll-up; change-management policy. Competitive cross-references placeholder pending `portal_competitive_benchmark.md`. |

---

## Reference

- **Google SRE Book — Service Level Objectives** (Ch. 4)
  <https://sre.google/sre-book/service-level-objectives/>
- **Google SRE Workbook — Implementing SLOs** (Ch. 2)
  <https://sre.google/workbook/implementing-slos/>
- **Google SRE Workbook — Alerting on SLOs** (multi-window burn-rate alerts, Ch. 5)
  <https://sre.google/workbook/alerting-on-slos/>
- **Atlassian Statuspage — SLA / SLO conventions**

---

## Definitions used in this document

| Term | Definition |
|---|---|
| **SLI** (Service Level Indicator) | A quantitative measurement of a thing the customer cares about — e.g. "fraction of API requests served < 500 ms with a 2xx response." |
| **SLO** (Service Level Objective) | The target value of an SLI over a measurement window — e.g. "99.5% of requests over rolling 30 days." |
| **SLA** (Service Level Agreement) | The contractual commitment to a tier of customers, derived from one or more SLOs with margin. The Portal's per-tier SLAs are in `portal_capabilities_brief.md` §6.4. |
| **Error budget** | `1 − SLO` over the window — e.g. a 99.5% SLO over 30 days permits ~3 h 36 min of unavailability. |
| **Burn rate** | How fast the error budget is being consumed relative to the budget window. Burn rate > 1 means the budget will be exhausted before the window resets. |
| **Slow burn / fast burn alerting** | Two parallel alert thresholds — slow burn catches a leaky regression over hours, fast burn catches an outage in minutes. Both close together to keep alerting precise without missing fast outages. |

---

## Why per-surface, not per-Portal-as-a-whole

A 99.9% Portal-wide SLO with everything bundled is operationally
meaningless: some surfaces are tolerant of brief outage (CVE feed
ingest from NVD; customers don't directly call it) while others must
always be available (per-tenant auth on every request; the customer
feed API). Each surface gets its own SLI/SLO; the fleet-wide promise
to customers is a *composition* of the per-surface budgets, not an
average.

This also means a release can blow the budget on a non-critical
surface without affecting the critical-path budget for the customer
feed API — useful for change-management policy below.

---

## Common SLI shapes used below

- **Availability (request-success ratio)** — `2xx_or_3xx_count / total_request_count`. The default for synchronous APIs.
- **Latency (request-success-within-threshold ratio)** — `requests_below_threshold_count / total_request_count`. Pairs with availability; e.g. "99% of successful requests under 200 ms."
- **Freshness (lag from upstream event to availability)** — for ingestion surfaces. E.g. "time from NVD publication of a CVE to that CVE being available in `cve_events`."
- **Throughput / saturation** — for batch / streaming surfaces. E.g. "fraction of inventory upsert requests absorbed within tenant rate limit without 429."
- **Durability (data loss frequency)** — for the data plane. Typically expressed as "zero data-loss events per measurement window" because any nonzero is unacceptable.

---

## Measurement window

**Rolling 30 days** for all SLOs below unless otherwise noted. Long
enough to absorb short outages without false alarms; short enough
that a chronic regression is visible.

Per Google SRE practice, alerts fire on **burn rate**, not on SLO
violation: a fast-burn alert at the equivalent of "would consume 5%
of the budget in 1 hour" catches outages, a slow-burn alert at the
equivalent of "consuming 10% of the budget over 6 hours" catches
chronic regressions. Both close together at a 5-minute window.

---

## Structure

Per surface: **What it does** • **SLIs** (quantitative measurements,
data source) • **SLO targets by tier** • **Error budget arithmetic** •
**Linked A1 gap or change-management implication**.

---

## Surface 1 — Operator admin API (`/api/admin/v1/*`)

### What it does
Operators (Red Hat or partner) create/edit tenants, manage tokens,
trigger feed runs, curate classification taxonomy, manage per-tenant
enrollments. Used by the Portal's operator web console and by ad-hoc
ops scripts.

### SLIs

| SLI | Definition | Data source |
|---|---|---|
| **Availability** | Fraction of `/api/admin/v1/*` responses with status 2xx or 3xx | nginx access log or FastAPI middleware |
| **Latency** | Fraction of successful admin requests served < 500 ms | FastAPI timing middleware |

### SLO

| Tier | Availability SLO (30d) | Latency SLO (30d) | Error budget (30d) |
|---|---|---|---|
| (admin surface — no per-tier variation; operator-only) | **99.5%** | **99% < 500 ms** | ~3 h 36 min of unavailability |

### Rationale

Admin is **internal-only**. An outage degrades operator productivity
but not customer-visible behavior. 99.5% is appropriate; pushing to
99.9% would consume engineering effort without customer benefit.

### Linked A1 gap / change-management implication

- Cross-refs: A1 gaps O1 (per-tenant observability — admin actions need attribution), O3 (canary deploys).
- A canary release that breaks admin can flip the slow-burn alert
  but is below the critical-path budget; release proceeds with a
  rollback ready, not a stop-the-line.

---

## Surface 2 — Customer CVE feed API (`/api/portal/v1/tenants/{id}/cves`)

### What it does
The customer-facing primary product surface. AAC bridges at the
customer site poll this endpoint every N minutes (configurable per
tenant — see `portal_capabilities_brief.md` §6.4) to receive matched
CVEs.

### SLIs

| SLI | Definition | Data source |
|---|---|---|
| **Availability** | Fraction of `/cves` GETs with status 2xx | FastAPI middleware |
| **Latency** | Fraction of successful `/cves` GETs served < 200 ms | FastAPI middleware |
| **Correctness** | Fraction of polls that delivered the matches expected (no double-delivery, no missed match within the tenant's polling cadence) | Application-emitted custom metric, cross-checked against `tenant_cve_matches.delivered_at` |

### SLO

| Tier | Availability SLO | Latency SLO | Correctness SLO | Error budget |
|---|---|---|---|---|
| Free | 99% / 30d | 99% < 1000 ms | 99% | ~7 h 12 min |
| Standard | 99.5% / 30d | 99% < 500 ms | 99.9% | ~3 h 36 min |
| Premium | **99.9% / 30d** | 99% < 200 ms | 99.99% | ~43 min |
| Air-gapped | self-hosted — operator's own SLO | n/a | n/a | n/a |

### Rationale

This is **the** customer-facing surface. An outage here means CVE
remediation lag, which means security risk for the customer's
environment. Premium tier's 99.9% is the highest in the Portal
because the customer pays for it and the bridge is polling
expecting to find the data.

### Linked A1 gap / change-management implication

- Cross-refs: A1 gaps R1 (rate limits), R2 (blue-green deploys), P1 (durable async).
- This SLO directly gates the change-management policy. Any release
  that consumes >5% of the Premium budget in 1 hour triggers
  automated rollback.
- A canary that exposes >2% of Premium-tier-traffic gets blocked
  until SLI metrics are clean.

---

## Surface 3 — Customer tenant auth (`require_tenant`)

### What it does
Every customer-facing API request authenticates via `require_tenant`
in `api/src/core/tenant_auth.py`. Bcrypt-verifies the bearer against
`tenant_tokens.token_secret_hash`. On the hot path of literally every
customer call.

### SLIs

| SLI | Definition | Data source |
|---|---|---|
| **Availability** | Fraction of `require_tenant` checks that complete (return tenant context or 401/403) without 5xx | FastAPI dependency middleware |
| **Latency** | Fraction of `require_tenant` checks served < 50 ms | FastAPI dependency middleware (bcrypt is the bottleneck) |
| **False-rejection rate** | Fraction of valid token presentations rejected (a regression here cuts off paying customers from their feed) | Tested via synthetic per-tenant probes; should be effectively zero |

### SLO

| Tier | Availability SLO | Latency SLO | False-rejection SLO | Error budget |
|---|---|---|---|---|
| All tiers | **99.95% / 30d** | 99.9% < 50 ms | **100%** | ~22 min |

### Rationale

This surface is the **multiplier** behind every other customer-facing
surface. A failure here cascades into Surface 2 and every customer
feature. Tighter SLO than the surfaces it underpins.

False-rejection SLO is "100%" — any rejection of a valid token is
treated as a stop-the-line incident.

### Linked A1 gap / change-management implication

- Cross-refs: A1 gaps S1 (operator OIDC SSO — separate auth path),
  S3 (Postgres RLS — defense in depth).
- Any release that touches `tenant_auth.py` must include synthetic
  probe coverage for all active tenants. A change-management
  pre-flight check.

---

## Surface 4 — CVE feed ingestion (NVD / CISA KEV / future PSIRT)

### What it does
Scheduled ingest jobs fetch new CVEs from upstream sources, upsert
into `cve_events`, run auto-classification. Async; runs ahead of
customer-facing demand.

### SLIs

| SLI | Definition | Data source |
|---|---|---|
| **Freshness** | Time from upstream publication of a CVE to that CVE being available in `cve_events` | Application timestamp + reconciliation against upstream feed timestamps |
| **Completeness** | Fraction of upstream CVEs successfully ingested (no permanent drops) | Reconciliation against upstream count |
| **Ingest-job success rate** | Fraction of scheduled ingest job runs that complete without error | `feed_runs.status` field |

### SLO

| Tier (delivered freshness; ingest itself is operator-side) | Freshness SLO | Completeness SLO | Ingest-job success SLO |
|---|---|---|---|
| Free | < 24 h (delivered to tenant) | 99% / 30d | 99% / 30d |
| Standard | < 1 h (delivered to tenant) | 99.9% | 99.5% |
| Premium | < 5 min (delivered to tenant) | 99.99% | 99.9% |

Note: these are *delivered* freshness SLOs, not ingestion-only. The
ingestion pipeline alone targets < 1 hour from upstream publication
on the operator side; the per-tier targets above include the
polling cadence allowed at each tier.

### Rationale

Customers don't directly observe ingest — they observe the *result*
through Surface 2. So the customer-visible freshness target combines
ingest delay + tenant polling cadence. Free tier is daily polling,
so 24 h freshness; Premium tier is real-time push (Piece 22 in
brief), so 5 min.

### Linked A1 gap / change-management implication

- Cross-refs: A1 gaps P1 (durable async queue), R7 (graceful
  degradation when an upstream is down).
- If NVD is down for 6 h, freshness SLO is consumed by external
  failure. The error budget records who consumed what; the
  retrospective decides whether to invest in mitigations (e.g.,
  fall back to NIST CVE feed mirror).

---

## Surface 5 — Classification + matching engine

### What it does
Runs after new CVEs land or after new inventory is pushed. Joins
inventory × CVEs × tags × enrollments × preferences → writes
`tenant_cve_matches` with `delivered_at = NULL` for new matches.
Tenants then consume via Surface 2.

### SLIs

| SLI | Definition | Data source |
|---|---|---|
| **Match-engine latency** | Time from new CVE landing in `cve_events` (or new inventory in `tenant_inventory_catalog`) to the first match row appearing in `tenant_cve_matches` for the affected tenant | Application timestamps |
| **Match correctness** | Fraction of seeded test matches found by the engine in QA runs (continuous regression test) | Automated test harness |
| **Throughput / saturation** | Match-engine wall-clock per-tenant run vs configured budget (matches: noisy-neighbor budget from A1 R6) | Custom metric |

### SLO

| Tier | Match latency | Match correctness | Throughput SLO |
|---|---|---|---|
| Free | < 1 h | 99.5% | n/a (best-effort) |
| Standard | < 15 min | 99.9% | < 30 sec wall-clock per match-run |
| Premium | < 5 min | 99.99% | < 10 sec wall-clock per match-run |

### Rationale

Match-engine latency is the gating delay between a CVE landing and
the customer learning about it. Tier discrimination is justified:
Premium customers (regulated, high-risk) pay for faster matching.

### Linked A1 gap / change-management implication

- Cross-refs: A1 gaps P1 (durable async), P3 (table partitioning),
  R6 (noisy-neighbor compute caps).
- Match correctness has a continuous-regression test built into the
  release pipeline. Releases that fail the test are blocked.

---

## Surface 6 — Per-tenant inventory upsert (`/api/admin/v1/tenants/{id}/inventory/upsert`)

### What it does
AAC bridges at the customer site push inventory daily (or more often
on Premium). Throughput-bound surface: incoming data flows could be
large (10K-100K rows per tenant).

### SLIs

| SLI | Definition | Data source |
|---|---|---|
| **Availability** | Fraction of inventory POSTs returning 2xx | FastAPI middleware |
| **Throughput** | Fraction of inventory POSTs absorbed within the tenant's configured rate limit (no 429) | Rate-limiter custom metric |
| **End-to-end ingest latency** | Time from inventory POST to those new rows being visible to the matching engine | Application timestamps |

### SLO

| Tier | Availability | Throughput-without-429 | Ingest latency |
|---|---|---|---|
| Free | 99% | 95% | < 1 h |
| Standard | 99.5% | 99% | < 15 min |
| Premium | 99.9% | 99.9% | < 5 min |

### Rationale

Inventory is a write-heavy surface. The rate limit is part of the
SLO contract — Free-tier customers POSTing too aggressively get
expected 429s; Premium-tier customers get higher absolute limits.
**The rate limiter (A1 gap R1) is a hard prerequisite for this
surface to have a meaningful SLO at all.**

### Linked A1 gap / change-management implication

- Cross-refs: A1 gap R1 (rate limiter) — blocks meaningful SLO until built.
- A1 gap R6 (noisy-neighbor caps) — once R1 ships, R6 becomes the
  follow-on protection.

---

## Surface 7 — Policy bundle delivery (Pieces 13-14 + 20)

### What it does
Operator publishes a Rego bundle (or a customer-managed-repo update
flows through Piece 20). Customer's AAC bridge polls on a schedule;
pulls the bundle; verifies signature; reloads OPA in bundle mode.

### SLIs

| SLI | Definition | Data source |
|---|---|---|
| **Availability** | Fraction of bundle GET requests returning 2xx | nginx / FastAPI middleware |
| **Bundle freshness** | Time from operator publishing a bundle to the customer's bridge having pulled it | Application timestamp + bridge heartbeat (A.A7 in `portal_data_flows.md` once that's written) |
| **Signature-verification correctness** | 100% — a bundle that fails signature verification on the customer side is a Sev 1 incident | Bridge-side reporting |

### SLO

| Tier | Availability | Bundle freshness | Signature correctness |
|---|---|---|---|
| Free | 99% | < 7 days | 100% |
| Standard | 99.5% | < 24 h | 100% |
| Premium | 99.9% | < 1 h (push on publish) | 100% |
| Air-gapped | n/a — bundle is delivered out-of-band | < (operator-published cadence) | 100% |

### Rationale

Bundle delivery is the "supply line" for compliance policy. If it
stalls, customers run stale policies — they may pass an audit with
a policy that's been superseded. Premium tier gets push-on-publish
because regulated customers can't wait a day.

Signature correctness SLO of 100% is non-negotiable; any signature
failure is a chain-of-custody incident.

### Linked A1 gap / change-management implication

- Cross-refs: This surface depends on AAC task #45 (OPA bundle mode)
  on the customer side. SLO measurement requires the bridge to
  report bundle versions, which depends on A.A7 (heartbeat) being
  built.

---

## Surface 8 — Operator + customer browser apps (React)

### What it does
Browser UI for operators (admin console) and customer end-users
(My Products). Calls Surfaces 1, 2, 3 below.

### SLIs

| SLI | Definition | Data source |
|---|---|---|
| **Page-load availability** | Fraction of full page loads completing without 5xx on any contained API request | Real User Monitoring (RUM) — to be added |
| **Time-to-interactive** | Median time from URL navigation to interactive page | RUM |
| **JS error rate** | JS errors per page load | RUM + frontend error tracker |

### SLO

| Tier | Availability | Time-to-interactive | JS error rate |
|---|---|---|---|
| All tiers | 99% / 30d | P50 < 3 s | < 1 error per 100 page loads |

### Rationale

Browser apps inherit the API SLOs underneath them. Looser
front-end-specific targets are appropriate because the user can
typically refresh and retry. Customer-facing My Products is the
critical front-end; operator console outage hurts ops but not
revenue.

### Linked A1 gap / change-management implication

- Cross-refs: A1 gap P4 (CDN not configured).
- Front-end SLI measurement requires RUM (Real User Monitoring)
  instrumentation — not yet present. A pre-req for honest SLO
  reporting on this surface.

---

## Surface 9 — PostgreSQL (the shared data plane)

### What it does
Every surface above eventually hits Postgres. A failure here
cascades.

### SLIs

| SLI | Definition | Data source |
|---|---|---|
| **Availability** | Fraction of database queries completing without connection error or timeout | asyncpg pool metrics / pg_stat_database |
| **Durability** | Frequency of data-loss events. Should be effectively zero. | Operational ledger; tested via DR drills |
| **Backup freshness** | Time between successful, verified backups | Backup pipeline emit |
| **Backup restore-success rate** | Fraction of DR-drill restore attempts that complete and pass integrity checks | DR-drill report |

### SLO

| Tier | Availability | Durability | Backup freshness | Restore-success |
|---|---|---|---|---|
| All tiers (cascades to everything) | **99.95% / 30d** | 100% (zero data-loss events) | ≤ 24 h | 100% across at least one drill per quarter |

### Rationale

Postgres is the foundation. Its SLO is tighter than any surface it
underpins because every minute of unavailability multiplies into the
nine surfaces above. Durability is binary — any nonzero data-loss
event triggers all-hands.

### Linked A1 gap / change-management implication

- Cross-refs: A1 gaps R3 (multi-AZ), R4 (DR runbook), R5 (selective
  tenant restore).
- The "backup restore-success" SLO requires the DR drill (R4) to
  exist. Drill itself is the SLO-defining event.

---

## Composite SLA promise per tier

The promise the Portal makes to customers (per `portal_capabilities_brief.md`
§6.4) is a function of the per-surface SLOs above. Mapping back:

| Tier promise (capabilities brief §6.4) | Composed from these surface SLOs |
|---|---|
| **Portal API uptime: best-effort (Free)** | Surfaces 2, 3, 6 at 99% / 99.95% / 99% — effective tier promise: ~99% / month |
| **Portal API uptime: 99.5% (Standard)** | Surfaces 2, 3, 6 at 99.5% / 99.95% / 99.5% — effective ~99.4% (worst-of) |
| **Portal API uptime: 99.9% (Premium)** | Surfaces 2, 3, 6 at 99.9% / 99.95% / 99.9% — effective ~99.85% (worst-of) |
| **CVE feed freshness: hourly (Standard) / push (Premium)** | Surfaces 4 + 5 freshness SLOs |
| **Policy bundle freshness: weekly (Free) / daily (Standard) / on-publish (Premium)** | Surface 7 freshness SLOs |

The composition reveals where promised SLAs are tighter than the
underlying surface SLOs support. **For Premium, the 99.9% promise
requires every component SLO to be 99.95% or better; only Surface
3 and Surface 9 meet that today even on paper.** Two paths to close
the gap:

1. Tighten Surface 2 SLO from 99.9% to 99.95% (engineering cost: significant; requires R1 + R2 closed).
2. Lower the Premium SLA promise to 99.85% to reflect what's actually deliverable.

Option 1 is the right answer if Premium is a revenue-anchor tier.
Option 2 is the right answer if first-customer is more important
than the marketing claim.

---

## Change-management policy

Now the policy can have teeth.

### Release gate

A release is **gated by the error budget on its blast radius**:

| Release type | Gating SLO | Action on burn |
|---|---|---|
| Admin-only change (operator console, internal scripts) | Surface 1 budget | Slow burn → continue with monitoring; fast burn → rollback |
| Customer-facing API change (Surfaces 2, 3, 6) | Premium-tier composite budget | Slow burn → rollback within 1 hour; fast burn → automated rollback |
| Background-only change (Surfaces 4, 5) | Standard-tier freshness budget | Slow burn → continue; fast burn → rollback |
| Schema change (touches Surface 9) | Surface 9 budget + dry-run on canary tenant | Any production durability event → all-hands |
| Bundle-format change (Surface 7) | Surface 7 budget + bridge-side signature-verification dry-run | Signature failure on canary → block release |

### Burn-rate alerts

Per Google SRE multi-window burn-rate practice:

| Window | Threshold | Alert |
|---|---|---|
| 1 h slow burn | > 1% budget consumed | Slack notification — investigate |
| 1 h fast burn | > 5% budget consumed | Page on-call |
| 6 h slow burn | > 10% budget consumed | Page on-call |
| 30 d at burn rate > 1 | Budget will exhaust before window resets | Stop-the-line — no non-critical releases until investigated |

### Where the budget is spent matters

- Self-inflicted budget burn (a bug that we shipped) → triggers a
  retrospective and a process investment.
- External-cause budget burn (NVD outage, customer's AWS region
  going down) → recorded but does not trigger a process change
  unless it accumulates.

### When a tier is repeatedly over-budget

A tier whose customers exhaust the error budget more than once per
quarter without single-incident root cause should have its SLA
promise re-examined. Either the tier is being sold to customers who
can't tolerate the budget, or the underlying SLO needs more
engineering investment.

---

## What this section enables once shipped

Concretely, with SLOs in place:

1. **Customer support gets data.** When a customer says "the feed is slow," the SRE-on-call can look at Surface 2 latency against SLO and answer empirically.
2. **Change management gets teeth.** A release that would breach Surface 2 latency is blocked at canary, not at "in production after customers complain."
3. **Tier pricing gets math.** Premium customers pay for a 99.9% promise that's deliverable; Free customers don't pay for a guarantee they don't have.
4. **Investment priorities get pointers.** The error budget tells you which surface to invest in next — the one whose budget customers exhaust first.

---

## What's required to ship this end-to-end

| Pre-req | Status | Comments |
|---|---|---|
| Tenant-tagged structured logging + metrics | ⏳ A1 gap O1 / brief Piece 30 | All SLI measurement depends on this |
| RUM instrumentation in the React apps | ⏳ Not started | Required for Surface 8 SLO measurement |
| Rate limiter | ⏳ A1 gap R1 / brief Piece 27 | Required for Surface 6 SLO to be meaningful |
| Custom metrics for bcrypt auth latency | ⏳ Not started | Required for Surface 3 SLO measurement |
| Async queue for matcher | ⏳ A1 gap P1 / proposed Piece 41 | Required for Surface 5 SLO measurement |
| Bridge-side heartbeat with bundle-version reporting | ⏳ A.A7 in data flows doc | Required for Surface 7 freshness measurement |
| Backup verification + DR drill cadence | ⏳ A1 gap R4 / brief Piece 31 | Required for Surface 9 backup/restore SLO |
| Burn-rate alert rules + on-call rotation | ⏳ Not started | The change-management policy assumes this exists |

Until those land, the SLOs above are **targets**, not measured. The
first six months of post-shipping work is acquiring the instrumentation
to measure them.

---

**Authored with Claude (Anthropic).**
