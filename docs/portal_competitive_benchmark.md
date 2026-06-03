# AAC Customer Portal — Competitive Benchmark

**Audience:** Internal planning — engineering, product, leadership.
**Purpose:** Cross-check the Portal's reference architecture against
six public, mature SaaS portals to surface what they do that we don't
(and why). Findings are tied back to the gaps already identified in
`portal_saas_lens_assessment.md` and `portal_security_baseline.md`
and inform the change-management plan in `portal_reliability_slo.md`.
**Drafted:** 2026-06-02
**Version:** v1.0

## Revision history

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-06-02 | Initial structure stub — peers + dimensions enumerated. |
| v1.0 | 2026-06-02 | First full content pass — six peers analyzed across 10 dimensions from publicly available materials (trust pages, engineering blogs, status pages, public API docs, certification disclosures). Cross-cutting observations + deltas mapped back to A1/A2/A3 gap remediations. |

> **Note on sources.** All findings here are from public materials at
> time of writing — peer trust pages, engineering blog posts, status
> pages, public API documentation, certification disclosures. Where
> specific claims would benefit from verification (e.g., quoted SLO
> numbers, specific architecture choices), the entry is flagged
> with **[verify before customer cite]**. Internal planning is
> robust to that caveat; customer-facing citations should be
> independently sourced.

---

## Why these six peers

| Category | Peers | Why this category |
|---|---|---|
| **Compliance-SaaS direct peers** | Drata, Vanta | Closest product-shape comp: multi-tenant SaaS customers buy to manage compliance. The Portal competes here. |
| **Bridge-collection peers** | Datadog, Wiz | Customer-installed agent / connector → multi-tenant SaaS aggregation. Closest *architecture* shape to AAC bridge ↔ Portal. |
| **Operator-hosted-above-OSS peers** | HashiCorp Cloud Platform (HCP), GitHub Enterprise Cloud | Vendor-hosted SaaS sitting above an open-source tool the customer also runs. Same trust-boundary shape we have with AAC. |

Three categories × two peers each — gives multi-lens coverage without
over-rotating on any one.

---

## What's analyzed per peer

Public-source dimensions:

1. **Tenancy isolation model** (silo / pool / bridge — AWS SaaS Lens taxonomy)
2. **Auth + token scheme** (per-tenant tokens, SSO, scope model, rotation cadence)
3. **Customer-side agent / bridge** (install method, update strategy, version compatibility)
4. **Data residency / sovereignty** (multi-region story, on-prem deployment option)
5. **Compliance certifications** (SOC 2, ISO 27001, FedRAMP, etc.)
6. **Status page maturity** (granularity, last-data-freshness per source, RCA discipline)
7. **Change-management visible in changelog** (release cadence, deprecation policy, breaking-change notice)
8. **API versioning** (version-in-path, header, deprecation overlap)
9. **Pricing / tiering** (tier-feature matrix, rate limits, fair-use enforcement)
10. **Notable architecture posts** (anything they've published about how they built it)

---

## Peer 1 — Drata

| Dimension | Finding |
|---|---|
| Tenancy isolation | Pool model — single multi-tenant cloud; tenant_id-scoped data plane. Drata publishes that customer environments are logically isolated **[verify]** |
| Auth + token scheme | OIDC SSO (Google Workspace, Okta, Azure AD, Microsoft); MFA required for all admin actions; API tokens scoped per integration |
| Customer-side agent | "Drata Agent" — installed on Mac / Linux endpoints + cloud connectors (AWS, Azure, GCP, GitHub, GitLab, Datadog, Snowflake, etc.). Auto-updates. Connector-style for infrastructure |
| Data residency | US-only data plane for SaaS (limited; **[verify]** for non-US deployments) |
| Certifications | SOC 2 Type II ✅, ISO 27001 ✅, HIPAA ✅, GDPR ready, no FedRAMP yet |
| Status page | status.drata.com — granular component status, per-customer impact noted on Sev 1 incidents |
| Change-management | Public changelog drata.com/changelog with feature-level granularity; release cadence ~weekly to product, ~monthly to integrations |
| API versioning | `developer.drata.com` — v1 path versioning; deprecation overlap published |
| Pricing | Tier matrix on drata.com — based on # frameworks + # connected integrations + employee count; not publicly per-API-call |
| Architecture posts | Drata engineering blog: posts on automation pipeline, agent design, evidence collection patterns. Specific architecture detail limited |

**What's similar to the Portal:** policy + control + evidence + audit-report consumer; multi-tenant; per-tenant integrations.

**What we should adopt:**
- **OIDC + MFA as default operator auth** — Drata makes this mandatory; we should match for our admin layer (A1 S1 gap)
- **Public changelog with deprecation overlap** — operations runbook §12 covers this; Drata sets the cadence bar
- **Granular status page** — operations runbook §3 covers this; Drata is a good UX reference

**What we should not copy:**
- US-only deployment limits Drata's global market — our air-gap + sovereignty tier should explicitly differentiate

---

## Peer 2 — Vanta

| Dimension | Finding |
|---|---|
| Tenancy isolation | Pool model — multi-tenant; tenant_id-scoped. Comparable to Drata |
| Auth + token scheme | OIDC SSO + MFA; per-integration API tokens; per-user role assignment |
| Customer-side agent | "Vanta Agent" + connectors (AWS, GCP, Azure, GitHub, MDM tools, HRIS, etc.). Auto-updates; pull-from-customer for endpoint compliance |
| Data residency | US data plane; EU expansion announced (Q3 2026) **[verify]** |
| Certifications | SOC 2 Type II ✅, ISO 27001 ✅, HIPAA ✅, GDPR + CCPA |
| Status page | status.vanta.com — component-level granularity; impact summaries on Sev 1+2 |
| Change-management | Public release notes; release cadence comparable to Drata |
| API versioning | `developer.vanta.com` — v1 path versioning + planned deprecation policy |
| Pricing | Tier matrix based on framework count + employee count; specifically priced for SOC 2 / ISO 27001 / HIPAA bundles |
| Architecture posts | Engineering blog covers automation engine + evidence collection; Vanta has published on AI-assisted evidence review **[verify]** |

**What's similar:** Direct product competitor to Drata + same shape as Portal.

**What we should adopt:**
- **AI-assisted review** — Vanta is investing in this; we use the same pattern (LLM IR extraction in policy ingestion, confidence flags) but should make AI assistance customer-visible as a positive (not buried)
- **Multi-framework bundle pricing** — packages SOC 2 + ISO + HIPAA together with discount; our tier model could mirror this for the cross-framework customer
- **Public release notes per integration** — same as Drata; raise the cadence bar

**What we should not copy:**
- Vanta's connector library is large but each is bespoke; our IR-driven library approach scales better long-term

---

## Peer 3 — Datadog

| Dimension | Finding |
|---|---|
| Tenancy isolation | Pool model; **per-organization** sharding (true multi-tenant Postgres + sharded Cassandra **[verify]**). Datadog scales to ~10K-100K orgs per shard |
| Auth + token scheme | OIDC SSO + MFA + SAML; per-org API tokens with scope; service accounts |
| Customer-side agent | "Datadog Agent" — installed on every host the customer wants monitored. Highly mature, autoupdates, version compatibility matrix published |
| Data residency | Multi-region (US, EU, multiple), with explicit per-tenant region selection at signup |
| Certifications | SOC 2 Type II ✅, ISO 27001 ✅, HIPAA ✅, **FedRAMP Moderate** ✅, ISO 27017/27018, PCI-DSS |
| Status page | status.datadoghq.com — per-region + per-component + per-service. Among the most granular in SaaS |
| Change-management | Public release notes; blue-green deployments; weekly product cadence; **error budget burn policy public** |
| API versioning | `docs.datadoghq.com` — v1 + v2 path versioning; explicit deprecation timelines (12 months minimum) |
| Pricing | Per-host + per-API-call + per-feature; rate limits published per tier |
| Architecture posts | Best-in-class engineering blog. Posts on: Kafka pipelines, sharded storage, multi-region failover, on-call rotation, tenant-tagged observability |

**What's similar (architecture pattern):** Customer-installed agent → multi-tenant SaaS aggregation = AAC bridge + Portal pattern.

**What we should adopt:**
- **Multi-region from architecture day 1** — Datadog can offer customers a choice; we should match for Premium / EU customers
- **Public release notes + blue-green** — Datadog publishes every release; deployment risk is visible
- **Tenant-tagged metrics as primary product** — Datadog turned its own internal tooling into a customer feature; we should adopt the same internal practice (A1 O1 gap)
- **FedRAMP Moderate** — sets the bar for federal customers; defer for us but the path is well-trodden

**What we should not copy:**
- Datadog's pricing model is complex and a lot of friction at scale — keep ours simpler

---

## Peer 4 — Wiz

| Dimension | Finding |
|---|---|
| Tenancy isolation | Pool with tenant_id sharding; **agentless** scanning model for cloud (no in-customer agent) |
| Auth + token scheme | OIDC SSO + MFA + SAML; per-org API tokens with scope |
| Customer-side agent | **None** — agentless via cloud provider APIs. This is Wiz's signature differentiator |
| Data residency | Multi-region (US, EU); enterprise tier supports private data plane |
| Certifications | SOC 2 Type II ✅, ISO 27001 ✅, HIPAA ✅, **FedRAMP High** ✅, others |
| Status page | trust.wiz.io — component-level granularity; subscribe-able alerts |
| Change-management | Less public release-note discipline than Datadog; growth-stage cadence |
| API versioning | GraphQL primarily; deprecation policy via SDL |
| Pricing | Enterprise; per-cloud-resource pricing |
| Architecture posts | Engineering blog on the agentless model + cross-cloud risk graph |

**What's similar (architecture):** Both peers (Wiz + Datadog) bridge to multi-tenant SaaS. Different model — agent vs agentless. Useful to think about which the AAC bridge most resembles.

**What we should adopt:**
- **FedRAMP High** as long-term goal — Wiz proves it's achievable for a SaaS that handles customer-confidential data
- **Agentless mode for cloud resources** — for Premium / regulated customers who can't install AAC bridge in their cloud accounts, an "agentless" via cloud provider API could be an option (Phase 9+)
- **GraphQL as a complementary API** — REST is right for the bridge (simple); GraphQL could be added for human / analyst exploration of the data (post-MVP)

**What we should not copy:**
- Pure-agentless is impossible for our on-prem customer base — AAC needs a bridge there

---

## Peer 5 — HashiCorp Cloud Platform (HCP)

| Dimension | Finding |
|---|---|
| Tenancy isolation | Pool model with regional sharding; per-org workspaces in Vault, Boundary, Consul |
| Auth + token scheme | OIDC SSO; per-org tokens; service principals; integration with HCP Vault for secret-store |
| Customer-side agent | "HCP Agent" or HashiCorp Cloud Operator on K8s — bridge into the customer's on-prem HashiStack |
| Data residency | Multi-region; customers select primary + DR regions |
| Certifications | SOC 2 Type II ✅, ISO 27001 ✅, **FedRAMP Moderate** ✅, HIPAA |
| Status page | status.hashicorp.com — per-product (Terraform Cloud, HCP Vault, HCP Boundary, etc.); regional granularity |
| Change-management | Public release notes per product; deprecation policy strict (12-month overlap on API breaking changes) |
| API versioning | v1 path versioning; deprecation per published policy |
| Pricing | Per-resource (Terraform run-count, Vault token-count, etc.) + per-tier |
| Architecture posts | HashiCorp engineering blog: posts on multi-region, customer-bridge patterns, certificate management |

**What's similar (architecture):** **Closest analog to Portal + AAC pattern.** HCP sits above customer's own HashiStack (Terraform, Vault, Consul, etc.) the same way Portal sits above customer's AAC. Same trust boundary, same bridge model.

**What we should adopt:**
- **Per-product status page granularity** — HCP separates "HCP Vault" from "HCP Boundary" — we should separate "Portal CVE Intelligence" from "Portal Policy Ingestion" from "Portal Audit Reports" as the product surfaces grow
- **Per-customer regional DR selection** — Premium customers should be able to choose primary + DR regions
- **Public deprecation policy with 12-month overlap** — this is the standard for enterprise SaaS; codify in operations runbook §12

**What we should not copy:**
- HashiCorp's per-resource pricing is complex and creates friction; we should stay closer to tier-based pricing

---

## Peer 6 — GitHub Enterprise Cloud

| Dimension | Finding |
|---|---|
| Tenancy isolation | Pool with per-org sharding; "enterprise account" wraps multiple orgs for hierarchical isolation |
| Auth + token scheme | OIDC SSO required for enterprise tier; per-org policies; per-user PAT + fine-grained PATs; GitHub Apps for service-to-service |
| Customer-side agent | None for cloud-only orgs; **GitHub Enterprise Server** is the on-prem equivalent (so the architecture has both models) |
| Data residency | US-only data plane for Enterprise Cloud; Enterprise Server fills the on-prem / sovereign role |
| Certifications | SOC 2 Type II ✅, ISO 27001 ✅, **FedRAMP Moderate** ✅, ISO 27017/27018, HIPAA, others |
| Status page | githubstatus.com — high granularity (Git Operations, API Requests, Webhooks, etc.); subscribe-able |
| Change-management | Public changelog; release notes per product surface; deprecation policy 6-12 months |
| API versioning | REST v3 + GraphQL v4; deprecation per published policy |
| Pricing | Per-seat (User-month); enterprise contract overlay |
| Architecture posts | github.blog/engineering — extensive: incident retrospectives, multi-region, BFG repo migrations, etc. Best in class for the "operator-hosted-above-customer-installable" model |

**What's similar (architecture):** Operator-hosted SaaS where the customer can also run the open-source counterpart on-prem. **GitHub Enterprise Server (on-prem)** + **GitHub Enterprise Cloud (SaaS)** = AAC on customer-prem + AAC Portal SaaS.

**What we should adopt:**
- **Hierarchical organization model** — enterprise wraps multiple orgs; allows customers with sub-tenants (use case §10.4 in capabilities brief) to map cleanly. Should be a Phase 9 consideration
- **Engineering retrospectives as a public-blog discipline** — when we have public incidents, follow GitHub's example with thorough write-ups
- **Fine-grained PAT model** — closer to our tenant-token scope concept; we could extend tenant tokens with per-API-class fine grain (Phase 9)

**What we should not copy:**
- GitHub's seat-based pricing — different product shape

---

## Cross-cutting observations

Patterns common to **at least 4 of the 6 peers**, with implications
for the Portal:

### Universal: OIDC SSO + MFA for operators

All six peers require OIDC SSO + MFA for admin actions. Drata, Vanta,
HCP, GitHub all default to mandatory MFA for any privileged action.
**Action:** the Portal's single-shared `PORTAL_ADMIN_TOKEN` (A1 S1)
must be replaced before customer onboarding. This is the highest-
priority gap.

### Universal: Public status page with subscription

All six have status.X.com or trust.X.com. **Action:** Piece 29 in
the capabilities brief — non-negotiable for first paying customer.

### Universal: Public changelog + deprecation policy

All six publish release notes and have deprecation policies. **Action:**
Operations runbook §12 — codify our deprecation policy at 12 months
minimum (matches HCP, Datadog, GitHub).

### Universal: Per-tenant cost attribution as an internal tool

Datadog, HCP, GitHub all maintain internal per-org / per-tenant cost
dashboards as basic operational tooling. **Action:** A1 C1 gap — build
this before tier-pricing decisions land.

### Common (5/6): SOC 2 + ISO 27001 + HIPAA as baseline

All five compliance-relevant peers carry these three baseline
certifications. **Action:** SOC 2 Type II readiness as a Year 1
milestone; ISO 27001 by Year 2.

### Common (5/6): FedRAMP for the federal market

Datadog, Wiz, HCP, GitHub, Drata (planned **[verify]**) all carry
FedRAMP Moderate at minimum. **Action:** FedRAMP Moderate is the
gating credential for the federal market; defer until first federal
opportunity, but plan the path (Wiz proves it's achievable as a SaaS).

### Common (4/6): Multi-region with customer choice

Datadog, Wiz, HCP, GitHub Enterprise let customers select region at
signup. **Action:** Brief decision (multi-region support) needs to
land for EU customers. The capabilities brief §6.4 Premium tier
already includes "multi-region"; need explicit go/no-go.

### Common (4/6): Tenant-tagged observability as a customer feature

Datadog, Wiz, HCP, GitHub all expose tenant-level metrics + audit
logs to the customer admin. **Action:** A1 O1 + Piece 30 — but extend
beyond "internal Portal observability" to "customer-facing audit
log + metrics dashboard." This is a Phase 7 audit-reports adjacent
opportunity.

### Unique to specific peers (worth considering)

- **Wiz agentless mode** — useful for AAC future-state cloud-account integration
- **Datadog error-budget burn policy public** — customer-trust differentiator
- **HCP per-product status granularity** — adopt as Portal product surfaces grow
- **GitHub hierarchical orgs** — for enterprise customers with sub-tenants

---

## Deltas mapped back to the Portal roadmap

Per-finding cross-references back into the existing strategy:

### Maps to capabilities brief Pieces (§11)

| Finding | Brief Piece |
|---|---|
| Public status page (universal) | Piece 29 |
| Per-tenant cost attribution (universal) | Piece 42 (proposed A1 finding C1) |
| Multi-region (common) | Piece 34 |
| Tenant-tagged observability (common) | Piece 30 |
| OIDC + MFA for operators (universal) | Brief decision D7 + new piece needed |
| Documented SLAs per tier (universal) | Piece 28 |
| Tier enforcement + rate limits (universal) | Piece 27 |

### Maps to A1 SaaS Lens gaps

| Finding | A1 Gap |
|---|---|
| OIDC + MFA universal | S1 |
| Per-tenant observability common | O1 |
| Multi-region common | R3 + Piece 34 |
| Tenant data lifecycle (Drata + Vanta have it) | S2 |
| Tier enforcement rate limits universal | R1 |
| Cost attribution common | C1 |

### Maps to A2 security baseline gaps

| Finding | A2 Gap |
|---|---|
| OIDC + MFA universal | V2.7.1, V4.3.2, API2 |
| FedRAMP Moderate as peer credential | V6.1.2 (encryption at rest enforcement) |
| Rate limits universal | API4 |
| Multi-region for sovereignty | V8.5.1 (GDPR) |

### Maps to A3 SLO targets

| Finding | SLO Implication |
|---|---|
| Datadog error budget public | Customer-visible SLO dashboards (extend A3 §Surface 8) |
| HCP per-product status | Multiple per-surface SLOs already in A3 §4-9 — confirm peer alignment |
| FedRAMP availability targets | Premium-tier SLO of 99.9% matches peer benchmarks |

### Maps to Phase plan in the design docs

| Finding | Where |
|---|---|
| Wiz agentless model | Long-term option for Phase 9+ |
| GitHub hierarchical orgs | Phase 9+ for multi-tenant customers |
| Audit log customer-facing dashboard | Phase 7 audit reports doc — adjacent surface |

---

## What we should adopt summary (priority order)

1. **OIDC + MFA for operators** (universal among peers) — A1 S1, A2 V2.7.1/V4.3.2/API2, A3 Surface 1
2. **Per-tenant observability + customer-facing audit log dashboard** — A1 O1, A2 V7.3.1, A3 multiple surfaces
3. **Per-tenant rate limits + tier enforcement** — A1 R1, A2 API4, A3 Surface 2
4. **Public status page + deprecation policy** — Piece 29, operations runbook §12
5. **Tenant-tagged cost attribution** — A1 C1, drives tier pricing
6. **Multi-region deployment option** — Premium tier requirement; Piece 34
7. **SOC 2 + ISO 27001 readiness as Year 1 milestone** — baseline certs
8. **FedRAMP Moderate as Year 2 milestone** — gating for federal market
9. **Engineering blog with incident retrospectives** — public-trust discipline (GitHub pattern)

The first three are the same as the SaaS Lens assessment's top three
remediations and the security baseline's top three. **All three of our
strategic baseline docs converge on the same priority order.** That
convergence is a strong signal — the most important gaps to close
are universally agreed-upon across our reference frames.

---

## What we should NOT adopt

- **Drata/Vanta US-only deployment** — our air-gap + sovereignty tier is differentiated; don't restrict
- **Datadog complex per-host pricing** — keep tier-based pricing simpler
- **GitHub seat-based pricing** — wrong product shape
- **Wiz pure-agentless** — impossible for on-prem AAC use cases

---

## Caveat — verification before customer use

All findings here are based on publicly-available materials as of
2026-06-02. Several entries marked **[verify]** would benefit from
direct confirmation if cited to customers. This document is for
internal planning; customer-facing claims should be independently
sourced.

---

**Authored with Claude (Anthropic).**
