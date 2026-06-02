# AAC Customer Portal — AWS SaaS Lens Assessment

**Audience:** Internal planning — engineering, product, leadership.
**Purpose:** Score the Portal against the AWS Well-Architected SaaS Lens
to surface architectural gaps before they become production
incidents. Findings feed the change-management plan in
`portal_reliability_slo.md` and the competitive-benchmark deltas in
`portal_competitive_benchmark.md`.
**Drafted:** 2026-06-02
**Version:** v0.1 (draft — content forthcoming)

## Revision history

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-06-02 | Initial structure stub — pillars enumerated; content forthcoming. |

---

## Reference

AWS Well-Architected Framework — SaaS Lens
<https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/saas-lens.html>

The SaaS Lens applies the six Well-Architected pillars
(Operational Excellence, Security, Reliability, Performance Efficiency,
Cost Optimization, Sustainability) to the unique concerns of a SaaS
business — tenant isolation, onboarding automation, per-tenant
observability, tier-aware cost, change velocity across a fleet.

---

## How this assessment is structured

Each pillar follows the same shape:

1. **Pillar principles** — the SaaS Lens's stated principles.
2. **Current state in the Portal** — what we have today, with code/file pointers.
3. **Gaps** — the delta from the principle, rated **L / M / H** for priority.
4. **Linked competitive observation** — what one or more of the six benchmark peers do here (see `portal_competitive_benchmark.md`).
5. **Recommended next steps** — concrete remediation tied to a Piece # in `portal_capabilities_brief.md` (§11) where applicable.

---

## 1. Operational Excellence

*Forthcoming.*

## 2. Security

*Forthcoming. Detailed control-by-control assessment in `portal_security_baseline.md`; this section is the SaaS-Lens-specific tenant-isolation and identity view.*

## 3. Reliability

*Forthcoming. Per-surface SLI/SLO targets in `portal_reliability_slo.md`; this section covers the SaaS-Lens architectural reliability concerns (multi-AZ, multi-tenant blast-radius containment, change deployment).*

## 4. Performance Efficiency

*Forthcoming.*

## 5. Cost Optimization

*Forthcoming.*

## 6. Sustainability

*Forthcoming.*

---

## Summary scorecard

*Forthcoming. Six pillars × {Strong / Adequate / Gap / Critical Gap}, with rollup to overall maturity.*

---

**Authored with Claude (Anthropic).**
