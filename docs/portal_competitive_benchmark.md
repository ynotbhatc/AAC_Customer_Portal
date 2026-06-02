# AAC Customer Portal — Competitive Benchmark

**Audience:** Internal planning — engineering, product, leadership.
**Purpose:** Cross-check the Portal's reference architecture against
six public, mature SaaS portals to surface what they do that we don't
(and why). Findings are tied back to the gaps already identified in
`portal_saas_lens_assessment.md` and `portal_security_baseline.md`
and inform the change-management plan in `portal_reliability_slo.md`.
**Drafted:** 2026-06-02
**Version:** v0.1 (draft — content forthcoming)

## Revision history

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-06-02 | Initial structure stub — peers + dimensions enumerated; per-peer content forthcoming. |

---

## Why these six peers

The Portal sits at the intersection of three peer categories. The
benchmark is anchored on the three categories — two peers each — so
we don't over-rotate on any single lens.

| Category | Peers chosen | Why |
|---|---|---|
| **Compliance-SaaS direct peers** | Drata, Vanta | Closest product-shape comp: multi-tenant SaaS that customers buy to manage compliance. The Portal directly competes here. |
| **Bridge-collection peers** | Datadog, Wiz | Customer-installed agent / connector → multi-tenant SaaS aggregation. Closest *architecture* shape to AAC bridge ↔ Portal. |
| **Operator-hosted-above-OSS peers** | HashiCorp Cloud Platform (HCP), GitHub Enterprise Cloud | Vendor-hosted SaaS sitting above an open-source tool the customer also runs. Same trust-boundary shape we have with AAC. |

---

## What's analyzed for each peer

Public sources only — trust pages, security white papers, engineering
blogs, status pages, changelogs, public API documentation, certification
disclosures.

Dimensions:

1. **Tenancy isolation model** — silo / pool / bridge (per AWS SaaS Lens taxonomy)
2. **Auth + token scheme** — per-tenant tokens, SSO, scope model, rotation cadence
3. **Customer-side agent / bridge** — install method, update strategy, version compatibility
4. **Data-residency / sovereignty** — multi-region story, on-prem deployment option
5. **Compliance certifications** — SOC 2, ISO 27001, FedRAMP, etc.
6. **Status page maturity** — granularity, last-data-freshness, RCA discipline
7. **Change-management visible in changelog** — release cadence, deprecation policy, breaking-change notices
8. **API versioning** — version-in-path, header-based, deprecation overlap window
9. **Pricing / tiering** — tier-feature matrix, rate limits, fair-use enforcement
10. **Notable architecture posts** — anything they've published about how they built it

---

## Peer 1 — Drata

*Forthcoming.*

## Peer 2 — Vanta

*Forthcoming.*

## Peer 3 — Datadog

*Forthcoming.*

## Peer 4 — Wiz

*Forthcoming.*

## Peer 5 — HashiCorp Cloud Platform (HCP)

*Forthcoming.*

## Peer 6 — GitHub Enterprise Cloud

*Forthcoming.*

---

## Cross-cutting observations

*Forthcoming. Patterns common to ≥ 3 of the six peers that the Portal
should adopt; patterns unique to one peer that may be a competitive
differentiator either way.*

---

## Deltas mapped back to the Portal roadmap

*Forthcoming. Per-finding cross-references back into:*
- *Pieces in `portal_capabilities_brief.md` §11*
- *Gaps in `portal_saas_lens_assessment.md`*
- *Gaps in `portal_security_baseline.md`*
- *SLO targets in `portal_reliability_slo.md`*

---

**Authored with Claude (Anthropic).**
