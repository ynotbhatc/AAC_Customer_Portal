# AAC Customer Portal — Reliability: SLIs, SLOs, Error Budgets

**Audience:** Internal planning — engineering, ops, product.
**Purpose:** Define measurable Service Level Indicators (SLIs), Service
Level Objectives (SLOs), and the error budgets they imply for every
surface of the Portal. Once these are in place, the change-management
policy gets teeth: a release that would consume more than the
remaining error budget is held back; a release that lands inside the
budget proceeds.
**Drafted:** 2026-06-02
**Version:** v0.1 (draft — content forthcoming)

## Revision history

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-06-02 | Initial structure stub — surfaces enumerated; targets forthcoming. |

---

## Reference

- **Google SRE Book — Service Level Objectives** (Ch. 4)
  <https://sre.google/sre-book/service-level-objectives/>
- **Google SRE Workbook — Implementing SLOs** (Ch. 2)
  <https://sre.google/workbook/implementing-slos/>
- **Atlassian Statuspage — SLA / SLO conventions**

---

## Definitions used in this document

| Term | Definition |
|---|---|
| **SLI** (Service Level Indicator) | A quantitative measurement — e.g. "fraction of API requests served < 500 ms with a 2xx status." |
| **SLO** (Service Level Objective) | The target value of an SLI over a measurement window — e.g. "99.5% over rolling 30 days." |
| **SLA** (Service Level Agreement) | The contractual commitment to a tier of customers, derived from one or more SLOs with margin. The Portal's per-tier SLAs are in `portal_capabilities_brief.md` §6.4. |
| **Error budget** | `1 - SLO` over the window — e.g. a 99.5% SLO over 30 days permits ~3 h 36 min of unavailability. |

---

## Why per-surface, not per-Portal-as-a-whole

A 99.9% Portal-wide SLO with everything bundled is meaningless to
operators because some surfaces are tolerant of brief outage (CVE feed
ingest from NVD) while others must always be available (per-tenant
auth, EDA bridge polling). Each surface gets its own SLI/SLO; the
fleet-wide promise to customers is a composition of the per-surface
budgets.

---

## Structure

Per surface: **What it does** • **SLIs** (quantitative measurements,
data source) • **SLO targets by tier** • **Error budget arithmetic**
• **Linked change-management implication** (what release behavior the
budget gates).

---

## Surface 1 — Operator admin API (`/api/admin/v1/*`)

*Forthcoming.*

## Surface 2 — Customer feed API (`/api/portal/v1/tenants/{id}/cves`)

*Forthcoming.*

## Surface 3 — Customer tenant auth (`require_tenant`)

*Forthcoming.*

## Surface 4 — CVE feed ingestion (NVD / CISA KEV / future PSIRT)

*Forthcoming.*

## Surface 5 — Classification + matching engine

*Forthcoming.*

## Surface 6 — Per-tenant inventory upsert (`/inventory/upsert`)

*Forthcoming.*

## Surface 7 — Policy bundle delivery (Piece 13-14)

*Forthcoming.*

## Surface 8 — Operator + customer browser apps (React)

*Forthcoming.*

## Surface 9 — PostgreSQL (the shared data plane)

*Forthcoming.*

---

## Composite SLA promise per tier

*Forthcoming. Maps the per-surface SLOs back to the tier-level
promises in the capabilities brief §6.4. The exercise will surface
any tier promise that's not actually supportable given current
infrastructure — those become commercial conversations before the
SLA reaches a customer contract.*

---

## Change-management policy implications

The error budget answers the operationally critical question: **"can
we ship this release without putting reliability at risk?"** The
mechanics:

- *Forthcoming.* Sketch: full budget consumed → freeze releases; budget
  spent on non-self-inflicted incidents (an upstream Microsoft Graph
  outage that we can't fix) → does NOT freeze releases; budget burned
  by a self-inflicted bug → triggers retrospective + investment in
  whatever testing/canary/rollback gap let it ship.

---

**Authored with Claude (Anthropic).**
