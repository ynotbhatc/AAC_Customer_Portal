# AAC Customer Portal — AWS SaaS Lens Assessment

**Audience:** Internal planning — engineering, product, leadership.
**Purpose:** Score the Portal against the AWS Well-Architected SaaS Lens
to surface architectural gaps before they become production
incidents. Findings feed the change-management plan in
`portal_reliability_slo.md` and the competitive-benchmark deltas in
`portal_competitive_benchmark.md`.
**Drafted:** 2026-06-02
**Version:** v1.0

## Revision history

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-06-02 | Initial structure stub — pillars enumerated. |
| v1.0 | 2026-06-02 | First full content pass — all six pillars scored with current state, gaps, priority, recommended next steps. Competitive cross-references are placeholders pending `portal_competitive_benchmark.md`. |

---

## Reference

AWS Well-Architected Framework — SaaS Lens
<https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/saas-lens.html>

---

## Portal architecture in one paragraph

For each pillar's analysis to mean anything, the architecture being
scored has to be visible up front:

- **Backend:** FastAPI + `asyncpg` pool to a single PostgreSQL 15 instance. Schema rooted on `tenant_id` UUID.
- **Frontend:** React 18 + Vite + TypeScript + Tailwind, served by nginx (sibling container).
- **Tenancy model:** **Pool** (per the SaaS Lens taxonomy) — a single FastAPI deployment + a single Postgres serve every tenant. Tenant isolation is by path (`/api/portal/v1/tenants/{tenant_id}/...`) plus per-tenant bcrypt-hashed bearer tokens that prove possession of the tenant.
- **Auth schemes (two today):** (1) Operator admin — single `PORTAL_ADMIN_TOKEN` env var, used by all admin operators. (2) Per-tenant — `tenant_secret` bcrypt-checked + `X-Token-Id` header.
- **Customer-side surface:** the AAC bridge (`ansible/roles/aac_portal_bridge/`) runs inside the customer environment, pulls feeds and pushes inventory.
- **Deployment topology assumed:** Operator-hosted (single region, single Postgres) as the default; self-hosted for air-gapped customers.

Critically — the Portal is **young**. It's been built up over the CVE Intelligence workstream (`feat/cve-intelligence` branches); the scorecard below reflects that. Many "gaps" are expected for a young multi-tenant system; the value is identifying *which* gaps must close before particular tenant counts, tiers, or trust requirements.

---

## How each pillar is scored

| Status | Meaning |
|---|---|
| **Strong** | Established practice; aligns with the SaaS Lens; no near-term work needed. |
| **Adequate** | Present but informal or partial; sufficient for current tenant count; will need attention before scale. |
| **Gap** | Specific principle of the pillar is not met; should land on a roadmap quarter. |
| **Critical Gap** | Architecture risk that could cause customer-visible incidents under current usage patterns or imminent growth. Should block tier/customer commitments until closed. |

Each gap includes a **priority** — Low / Medium / High — for relative urgency within the pillar. Priority ≠ status: a Gap may be Low priority because it doesn't bite until 1 000+ tenants; a Critical Gap is always at least Medium priority and usually High.

---

## 1. Operational Excellence

### Pillar principles (SaaS Lens)

The SaaS Lens applies five Operational Excellence principles to multi-tenant SaaS:

1. **Onboarding automation** — tenants come online without human-in-the-loop steps.
2. **Per-tenant observability** — every metric, log, and trace is tenant-attributable.
3. **Tenant-aware incident management** — incidents are scoped to "which tenants are affected" not "is the service up."
4. **Continuous improvement via game days** — controlled failure injection to find unknown failure modes before customers do.
5. **Multi-tenant deployment pipeline** — code reaches all tenants via a controlled rollout, not big-bang.

### Current state

| Principle | What we have today |
|---|---|
| Onboarding automation | Operator UI creates tenant + issues token. Roughly 30 seconds; no manual ops. `api/src/routers/tenants.py`. |
| Per-tenant observability | **None.** FastAPI request logs do not attach `tenant_id`. No tenant-tagged Prometheus metrics. No structured logging convention. |
| Tenant-aware incident management | **None formalized.** Incidents would have to be reconstructed from raw logs. |
| Continuous improvement via game days | **None.** No game-day cadence. No chaos engineering. |
| Multi-tenant deployment pipeline | **Big-bang.** A Portal deploy goes to all tenants simultaneously. No canary, no per-tier rollout. |

### Gaps

| # | Gap | Priority |
|---|---|---|
| O1 | Per-tenant observability is missing — every request log, metric, and trace should carry `tenant_id` as a structured field; the dashboards should default to "filter by tenant." | **High** |
| O2 | No incident severity matrix that includes tenant impact dimension (one tenant affected vs N tenants vs all tenants). | **Medium** |
| O3 | No canary or progressive rollout in the deployment pipeline. A bug ships to all tenants at once. | **High** |
| O4 | No game-day cadence. We've never validated that we know what happens when (NVD goes down / Postgres fails over / Redis cache empties / the bridge loses its token). | **Medium** |
| O5 | No formal post-mortem template or blameless retrospective discipline. | **Low** — fix once we have our first real incident |

### Linked competitive observation

*To be filled from `portal_competitive_benchmark.md`.* Expected patterns at completion: **Datadog publishes tenant-tagged metrics as a primary feature, and exposes per-organization audit logs as a first-class product capability.** Drata's status page shows per-customer impact during incidents. HCP rolls releases per region with auto-rollback on error-budget burn.

### Recommended next steps

| Step | Maps to brief Piece # | Effort |
|---|---|---|
| Add structured logging middleware that injects `tenant_id` into every request log + access log. | New — extension of brief Gap G2 | Days |
| Add Prometheus metrics tagged by `tenant_id`, `tier`, `endpoint`, `status_class`. | Piece 30 | Days |
| Define incident severity matrix (`incident_severity.md`) — Sev 1-4 mapped to tenant impact + customer comms cadence. | New | Days |
| Implement canary deployment for the Portal API — first to internal/test tenant, then 10% of Free, then 50%, then full. | New piece (defer for later sprint) | Weeks |
| Schedule first game day after SLOs are defined (depends on A3). | New piece | Days to prep |

### Status

**Gap** (would be Critical Gap once tenant count > 10). Per-tenant observability is the #1 blocker — without it the rest of the operational story is unmeasurable.

---

## 2. Security

> The detailed control-by-control assessment is in `portal_security_baseline.md` (OWASP ASVS L2 + API Top 10). This section covers only the SaaS Lens's specific tenant-isolation, identity, and SaaS-operations concerns.

### Pillar principles (SaaS Lens)

1. **Tenant isolation as a first-class invariant** — cross-tenant data exposure must be architecturally prevented, not merely policy-enforced.
2. **Identity per tenant, identity per actor** — operators and tenant users are distinct identity subjects with distinct authentication paths.
3. **Defense in depth across tenant boundaries** — multiple independent layers prevent one bug from compromising tenant isolation.
4. **Encryption in transit AND at rest** — both within the SaaS environment and on the wire to customer bridges.
5. **Tenant data lifecycle** — clear policy on data residency, export, retention, and deletion.
6. **Compliance posture of the SaaS itself** — the operator's certifications are part of the customer's trust decision.

### Current state

| Principle | What we have today |
|---|---|
| Tenant isolation | **Strong by construction.** Tenant ID is in the URL path; each request authenticates against a per-tenant bearer that is bcrypt-checked against `tenant_tokens`. Cross-tenant access requires forging both the path and the token. Code: `api/src/core/tenant_auth.py`. |
| Identity per tenant | **Strong.** Per-tenant tokens with scopes (`inventory_pull`, `cve_feed`), individually revocable, multiple-active-tokens-per-tenant for zero-downtime rotation. |
| Identity per operator actor | **Critical gap.** Single shared `PORTAL_ADMIN_TOKEN` env var. No distinction between operator-A and operator-B making an admin change. |
| Defense in depth | **Partial.** Token + path is one layer. No row-level security in Postgres (would be a second layer). No additional middleware enforcing tenant scope on queries. |
| Encryption in transit | **Assumed but not enforced.** Nginx sits in front; assumes HTTPS is terminated there. The FastAPI service itself does not require HTTPS. |
| Encryption at rest | **Not explicitly configured.** Depends on the host filesystem / Postgres deployment configuration. |
| Tenant data lifecycle | **Critical gap.** No documented export, no documented deletion, no retention policy beyond what Postgres holds forever. |
| Compliance of the SaaS | **None.** The Portal itself has no SOC 2 / ISO 27001 / FedRAMP certification or readiness work in flight. |

### Gaps

| # | Gap | Priority |
|---|---|---|
| S1 | Operator-side auth is a single shared token. Cannot attribute admin actions to individuals; cannot revoke one operator without rotating the token for all. | **High** |
| S2 | No tenant data lifecycle policy — export, deletion, retention. GDPR / SOC 2 readiness blocker. | **High** |
| S3 | Row-level security (RLS) in Postgres not enabled. A bug in the API layer could expose cross-tenant data via the database connection itself. | **Medium** |
| S4 | Encryption-at-rest not enforced by deployment configuration. | **Medium** |
| S5 | Encryption-in-transit not enforced inside the application (relies on nginx). | **Medium** |
| S6 | No threat model document for the Portal itself. Useful for design reviews and an eventual penetration test. | **Medium** |
| S7 | Portal compliance certification (SOC 2 Type II, ISO 27001) — commercial decision; technical work depends on it. | **Low** until first regulated customer engagement; **High** the moment one materializes |

### Linked competitive observation

*To be filled.* Expected: **all six benchmark peers have SOC 2 Type II as table stakes**; most have ISO 27001; the federal ones (Drata, Datadog) have FedRAMP Moderate. Operator-side auth in peers is OIDC SSO universally — single shared admin tokens are extinct in mature SaaS.

### Recommended next steps

| Step | Maps to brief Piece # / decision | Effort |
|---|---|---|
| Replace `PORTAL_ADMIN_TOKEN` with OIDC operator SSO (Okta/Auth0/internal IdP). | Brief decision D7 | Weeks |
| Write tenant data lifecycle policy + implement the export and delete endpoints. | New piece | Weeks |
| Enable Postgres row-level security on tenant-scoped tables. Defense in depth even if the API layer has a bug. | New piece | Days (policy) + days (testing) |
| Document encryption-at-rest expectation in the deployment guide; verify in each hosted environment. | Operations | Days |
| Author the Portal threat model (`docs/portal_threat_model.md`). | New | Days |
| Plan SOC 2 readiness assessment timing. | Commercial | Quarter-scale |

### Status

**Gap** — the construction is sound (tenant isolation is provable by path + token) but the operator-side and lifecycle work is not. **Critical Gap** the day the first regulated customer signs.

---

## 3. Reliability

### Pillar principles (SaaS Lens)

1. **Multi-AZ for the SaaS data and compute** — one infrastructure failure should not interrupt service.
2. **Tenant blast-radius containment** — one tenant's bad behavior (DoS-by-accident or hostile) must not affect other tenants.
3. **Noisy-neighbor controls** — compute and database resources are bounded per tenant.
4. **Change deployment that protects in-flight tenant operations** — releases happen without dropping requests or partially updating state.
5. **Backup and DR with selective tenant restore** — when something goes wrong for one tenant (data corruption, accidental delete), restore that tenant without rolling back everyone else.

### Current state

| Principle | What we have today |
|---|---|
| Multi-AZ | **Not enforced by code.** Depends on the deployment topology; a single-VM hosting collapses everything. |
| Tenant blast-radius containment | **None.** No rate limits per tenant; no quota on inventory size or feed-poll frequency. A tenant POSTing 100K inventory rows per minute would degrade the Portal for everyone. |
| Noisy-neighbor controls | **None.** Matching engine runs synchronously per-tenant on demand; no CPU or memory cap per run. |
| Change deployment | **Big-bang restart.** No blue-green, no rolling. The FastAPI service restarts and in-flight requests are dropped. |
| Backup and DR | **Schema-and-pg_dump capable** (PostgreSQL native) but no documented restore drill, no selective-tenant restore tested. |

### Gaps

| # | Gap | Priority |
|---|---|---|
| R1 | No per-tenant rate limiter. A noisy tenant takes down the Portal. | **Critical / High** |
| R2 | No blue-green or rolling deployment for the Portal API. Every release drops in-flight requests. | **High** |
| R3 | No multi-AZ enforcement in the deployment topology. Single-AZ outage = full outage. | **High** for hosted, **N/A** for self-hosted air-gap |
| R4 | No DR runbook + first restore drill. We don't know our RPO/RTO empirically. | **High** |
| R5 | No selective-tenant restore capability. One tenant's accidental delete → only option today is full-cluster point-in-time recovery. | **Medium** |
| R6 | No noisy-neighbor compute caps on the matching engine. A 100K-CVE × 50K-product tenant match could starve everyone. | **Medium** |
| R7 | No graceful degradation strategy. NVD outage today blocks the matching engine; we don't fall back to last-known-good. | **Medium** |

### Linked competitive observation

*To be filled.* Expected: **Datadog publishes per-org rate limits and quota walls in their public docs.** HCP runs rolling regional upgrades with auto-rollback on error-budget burn. Vanta has documented their DR drill cadence (quarterly).

### Recommended next steps

| Step | Maps to brief Piece # | Effort |
|---|---|---|
| Implement a rate-limiter middleware keyed on `tenant_id` × endpoint, with limits by tier. | Piece 27 | Days |
| Define blue-green or rolling deployment strategy for FastAPI; nginx upstream switching for the cutover. | New piece | Weeks |
| Write the DR runbook; execute a restore drill; capture empirical RPO/RTO; commit as `docs/dr_runbook.md`. | Piece 31 | Weeks |
| Add a noisy-neighbor budget on the matching engine (e.g. 5 minutes max wall-clock per match run; spill to background queue beyond that). | New piece (depends on async queue work in pillar 4) | Days |
| Define graceful-degradation behavior when an upstream feed source is down. | New piece | Days |

### Status

**Critical Gap.** R1 (no rate limits) is the single largest production risk in the assessment. Closing it should be ahead of any new tenant onboarding past the internal/test cohort.

---

## 4. Performance Efficiency

### Pillar principles (SaaS Lens)

1. **Right-size compute per tenant load** — autoscale or vertical-scale based on observed usage.
2. **Cache hot tenant data** — taxonomy, classification, frequently-read configuration.
3. **Async processing for non-interactive operations** — ingest, classification, matching, evidence generation belong off the request thread.
4. **Database sharding / partitioning at scale** — multi-tenant tables that grow linearly with (tenant_count × per-tenant data) need a plan before they hurt.
5. **CDN for static assets** — the React bundle should not be served from origin.

### Current state

| Principle | What we have today |
|---|---|
| Right-size compute | **Single FastAPI container.** No autoscaling. Vertical scaling is the only response to load. |
| Cache hot tenant data | **None.** asyncpg pool gives connection-level reuse, but no app-level cache (no Redis). Taxonomy + classification re-queried on every call. |
| Async processing | **In-process only.** FastAPI `BackgroundTasks` for feed ingest + matcher runs. **Lost on restart**, not durable. |
| Database sharding/partitioning | **None.** Single Postgres. Single (unpartitioned) tables for `cve_events`, `tenant_inventory_catalog`, `tenant_cve_matches`. Fine today (low double-digit tenants); problematic at 1 000+. |
| CDN | **None.** nginx in front; serves the React bundle from origin. |

### Gaps

| # | Gap | Priority |
|---|---|---|
| P1 | Feed ingest + matcher use FastAPI `BackgroundTasks`. Not durable: a restart loses in-flight work. Move to a durable queue (Redis Streams / RabbitMQ / SQS). | **High** |
| P2 | No app-level cache. Add Redis for taxonomy, per-tenant config, classification results. | **Medium** |
| P3 | No partitioning strategy for the growth-bound tables. The candidates are `cve_events` (grows with CVE rate, not tenant count), `tenant_inventory_catalog` and `tenant_cve_matches` (grow with both tenant count and per-tenant data volume). | **Medium** for `cve_events`; **High** for tenant tables at scale |
| P4 | No CDN. React bundle re-downloads per visit. | **Low** until customer-facing traffic justifies it |
| P5 | No FastAPI autoscaling. | **Low** until traffic > one container can handle |

### Linked competitive observation

*To be filled.* Expected: **Wiz publishes a Kafka-based async architecture** for cross-tenant aggregation. **Drata's engineering blog mentions Redis for caching tenant configuration.** Datadog runs sharded Postgres at scale (shard key = tenant).

### Recommended next steps

| Step | Maps to brief Piece # | Effort |
|---|---|---|
| Choose async queue technology (recommend Redis Streams as lowest-friction match for our stack). Migrate feed ingest + matcher to it. | New piece | Weeks |
| Add Redis cache for the hot-path reads. | New piece | Days |
| Document partitioning plan for the three growth-bound tables. Implement when tenant count > 500 or when single-table size > 100 GB, whichever first. | New piece | Document now, implement later |
| Defer CDN + autoscaling until SLOs (A3) tell us they're needed. | — | Defer |

### Status

**Adequate** for current tenant count (low double-digit). **Gap** at 100+. The async queue migration (P1) should land before tier enforcement (Piece 27) because rate limits + durable queues need to interact.

---

## 5. Cost Optimization

### Pillar principles (SaaS Lens)

1. **Per-tenant cost attribution** — every infrastructure dollar maps to a tenant.
2. **Tier-aware compute allocation** — Premium tenants get more compute footprint than Free.
3. **Reserved vs spot** — predictable load → reserved, batch work → spot.
4. **Per-tenant cost monitoring** — the operator sees unit economics per tenant in real time.
5. **Cost-aware feature design** — every feature has a known $-per-tenant impact.

### Current state

| Principle | What we have today |
|---|---|
| Per-tenant cost attribution | **None.** No mechanism to attribute compute, storage, or egress to a tenant. |
| Tier-aware compute allocation | **None.** Tier exists in `tenants.tier` but doesn't drive any compute / queue / cache decision. |
| Reserved vs spot | **N/A** without a known traffic pattern. |
| Per-tenant cost monitoring | **None.** |
| Cost-aware feature design | **Implicit.** Engineers consider cost informally; nothing measured. |

### Gaps

| # | Gap | Priority |
|---|---|---|
| C1 | No per-tenant cost attribution. Hard to price tiers correctly without it; impossible to identify unprofitable tenants. | **High** before tier-enforcement work (Piece 27) lands |
| C2 | No tier-aware compute allocation. Premium and Free tenants get the same throughput today. | **Medium** — defer until enforcement is built |
| C3 | No cost dashboard for the operator. | **Medium** |

### Linked competitive observation

*To be filled.* Expected: **all six peers maintain internal per-tenant unit economics dashboards** as a default operational tool. Datadog and HCP publish high-level pricing-and-margin pieces in their investor materials.

### Recommended next steps

| Step | Maps to brief Piece # | Effort |
|---|---|---|
| Add basic per-tenant cost attribution: tag every Postgres query and HTTP request with `tenant_id`; aggregate hourly into a `tenant_usage` table. | New piece | Days |
| Build the operator unit-economics dashboard from that table. | New piece | Days |
| Defer reserved vs spot until traffic pattern is known. | — | Defer |

### Status

**Gap.** Not customer-visible, so it's easy to deprioritize, but it gates correct tier pricing (decision D1 in the brief).

---

## 6. Sustainability

### Pillar principles (SaaS Lens)

1. **Right-sized infra** — reduces energy footprint by not over-provisioning.
2. **Carbon-aware region selection** — deploy in lower-carbon regions when possible.
3. **Efficient query patterns** — N+1 queries, large unnecessary scans, etc. cost energy as well as money.
4. **Minimize data movement and egress** — every byte across the wire has a carbon cost.
5. **Customer-facing sustainability disclosures** — large customers procure based on supplier carbon disclosures.

### Current state

Across the board: **not measured.** This is the lowest-priority pillar for a young SaaS but matters at scale.

### Gaps

| # | Gap | Priority |
|---|---|---|
| Su1 | No baseline of per-request energy / CO₂ cost. | **Low** — capture opportunistically once observability lands |
| Su2 | Carbon-aware deployment region selection not on the radar. | **Low** |
| Su3 | No customer-facing sustainability disclosure. | **Low** until first procurement asks for it |

### Linked competitive observation

*To be filled.* Expected: **Datadog publishes an annual sustainability report**; AWS and Azure both expose per-customer carbon dashboards. Most direct compliance-SaaS peers (Drata, Vanta) don't yet publish sustainability reports.

### Recommended next steps

| Step | Effort |
|---|---|
| Defer formal work until SOC 2 readiness or a customer procurement requirement, whichever comes first. | — |
| Capture baseline carbon metrics opportunistically once observability (O1) ships. | Hours |

### Status

**Adequate** — defer is the right call for a young SaaS.

---

## Summary scorecard

| Pillar | Status | Highest-priority gap | Critical gaps |
|---|---|---|---|
| **1. Operational Excellence** | Gap | O1 (per-tenant observability) | None blocking today; O1 + O3 (canary deploys) become blocking past ~10 tenants |
| **2. Security** | Gap | S1 (operator OIDC SSO), S2 (tenant data lifecycle) | None blocking today; S2 blocking the first GDPR or SOC 2 customer |
| **3. Reliability** | **Critical Gap** | R1 (per-tenant rate limits) | R1 — must close before any non-trial tenant onboards |
| **4. Performance Efficiency** | Adequate | P1 (durable async queue) | None blocking today; P1 + P3 become blocking at 100+ tenants |
| **5. Cost Optimization** | Gap | C1 (per-tenant cost attribution) | None blocking today; gates correct tier pricing |
| **6. Sustainability** | Adequate (defer) | Su1 | None |

### Overall

The Portal's tenant isolation and identity story are **strong by
construction** — those are the principles that are hardest to retrofit
and easiest to get wrong, so getting them right early is the right
prioritization.

The main risk areas, in order:

1. **Reliability — no per-tenant rate limits and no blue-green deploys.** Pillar 3 closes first.
2. **Operational visibility — no per-tenant observability.** Pillar 1's O1 unblocks everything downstream (SLO measurement, cost attribution, security audit logging) — it should be one of the very next pieces of work.
3. **Operator auth — single shared admin token.** Pillar 2's S1 is the biggest "this won't pass a security review" item.
4. **Tenant data lifecycle — no export, no delete, no retention.** Pillar 2's S2 is the biggest "this won't pass a privacy review" item.

These four items between them clear most of the production-readiness gap. Pillars 4 (performance), 5 (cost) and 6 (sustainability) can defer until tenant count or commercial readiness demand them.

### Mapping into the capabilities brief

The pieces that land first in priority order, with their brief mapping:

| Priority | Work | Brief Piece # |
|---|---|---|
| 1 | Per-tenant rate-limiter middleware (R1) | Piece 27 (tier enforcement) — covers it |
| 2 | Tenant-tagged structured logging + Prometheus metrics (O1) | Piece 30 (operator observability) |
| 3 | Blue-green deployment for Portal API (R2) | New — propose Piece 39 |
| 4 | OIDC operator SSO (S1) | Brief decision D7 |
| 5 | Tenant data lifecycle endpoints + policy (S2) | New — propose Piece 40 |
| 6 | DR runbook + first restore drill (R4) | Piece 31 |
| 7 | Durable async queue migration (P1) | New — propose Piece 41 |
| 8 | Per-tenant cost attribution + unit-economics dashboard (C1) | New — propose Piece 42 |

The four "new pieces" above (39, 40, 41, 42) should land in the next revision of `portal_capabilities_brief.md` §11.3.

---

**Authored with Claude (Anthropic).**
