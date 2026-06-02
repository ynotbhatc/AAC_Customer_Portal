# AAC Customer Portal — Security Baseline

**Audience:** Internal planning — engineering + security review.
**Purpose:** Self-assessment against the two layered security
standards most applicable to the Portal: **OWASP ASVS v4 Level 2**
(application-layer hygiene appropriate for a SaaS handling moderate-
sensitivity data) and **OWASP API Security Top 10 (2023)** (API-
specific risks). Findings feed the §A2 pillar of the SaaS Lens
assessment and the change-management policy.
**Drafted:** 2026-06-02
**Version:** v0.1 (draft — content forthcoming)

## Revision history

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-06-02 | Initial structure stub — both standards enumerated; content forthcoming. |

---

## Reference

- **OWASP ASVS v4** (Application Security Verification Standard, Level 2)
  <https://owasp.org/www-project-application-security-verification-standard/>
  Level 2 is the standard target for applications that handle business-
  to-business data and personally identifiable information without
  regulated (PCI / HIPAA / FedRAMP) requirements. Promotes to Level 3
  if/when the Portal lands a regulated tier of customer.

- **OWASP API Security Top 10 (2023)**
  <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
  The application-API-specific corollary; covers BOLA, broken auth,
  unrestricted resource consumption, server-side request forgery,
  etc.

---

## Why these two (and not, say, SOC 2)

ASVS + API Top 10 are **engineering-actionable** — they produce a
control-by-control checklist a development team can act on. SOC 2 / ISO
27001 are **organizational** standards: useful for the customer-facing
trust story but not directly mappable to code reviews. Once the
engineering controls are in place, the SOC 2 readiness assessment
becomes much shorter; that's tracked separately.

---

## Structure

Per control: **Status** (Met / Partial / Gap / N/A) • **Evidence**
(code path or memory pointer) • **Remediation** (action + owner) •
**Linked peer behavior** (cross-reference to `portal_competitive_benchmark.md`).

---

## Part 1 — OWASP ASVS v4 Level 2

### V1: Architecture, Design and Threat Modeling

*Forthcoming.*

### V2: Authentication

*Forthcoming.*

### V3: Session Management

*Forthcoming.*

### V4: Access Control

*Forthcoming.*

### V5: Validation, Sanitization and Encoding

*Forthcoming.*

### V6: Stored Cryptography

*Forthcoming.*

### V7: Error Handling and Logging

*Forthcoming.*

### V8: Data Protection

*Forthcoming.*

### V9: Communication

*Forthcoming.*

### V10: Malicious Code

*Forthcoming.*

### V11: Business Logic

*Forthcoming.*

### V12: Files and Resources

*Forthcoming.*

### V13: API and Web Service

*Forthcoming.*

### V14: Configuration

*Forthcoming.*

---

## Part 2 — OWASP API Security Top 10 (2023)

### API1:2023 — Broken Object Level Authorization (BOLA)

*Forthcoming.*

### API2:2023 — Broken Authentication

*Forthcoming.*

### API3:2023 — Broken Object Property Level Authorization

*Forthcoming.*

### API4:2023 — Unrestricted Resource Consumption

*Forthcoming.*

### API5:2023 — Broken Function Level Authorization

*Forthcoming.*

### API6:2023 — Unrestricted Access to Sensitive Business Flows

*Forthcoming.*

### API7:2023 — Server Side Request Forgery (SSRF)

*Forthcoming.*

### API8:2023 — Security Misconfiguration

*Forthcoming.*

### API9:2023 — Improper Inventory Management

*Forthcoming.*

### API10:2023 — Unsafe Consumption of APIs

*Forthcoming.*

---

## Summary scorecard

*Forthcoming. Per-section rollup and an overall L2 conformance percentage.*

---

**Authored with Claude (Anthropic).**
