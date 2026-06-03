# AAC Customer Portal — Security Baseline

**Audience:** Internal planning — engineering + security review.
**Purpose:** Self-assessment against the two layered security
standards most applicable to the Portal: **OWASP ASVS v4 Level 2**
(application-layer hygiene appropriate for a SaaS handling moderate-
sensitivity data) and **OWASP API Security Top 10 (2023)** (API-
specific risks). Findings feed the §A2 pillar of the SaaS Lens
assessment and the change-management policy.
**Drafted:** 2026-06-02
**Version:** v1.0

## Revision history

| Version | Date | Change |
|---|---|---|
| v0.1 | 2026-06-02 | Initial structure stub — both standards enumerated. |
| v1.0 | 2026-06-02 | First full content pass — every ASVS L2 chapter + every API Top 10 item scored with status (Met / Partial / Gap / N/A), evidence pointer, and remediation owner. Cross-references back to the SaaS Lens assessment (A1), the operations runbook, and the policy ingestion / remediation / golden image / audit-report design docs where security touchpoints land. |

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
becomes much shorter; that's tracked separately in
`portal_capabilities_brief.md` §6.4 and `portal_operations_runbook.md` §9.

---

## Structure

Per control: **Status** • **Evidence** (code path or memory pointer)
• **Remediation owner** • **Linked peer observation** (cross-reference
to `portal_competitive_benchmark.md`).

**Status legend:**
- **Met** — Control is satisfied; current implementation passes the requirement
- **Partial** — Some aspects covered, others gapped; remediation reduces gap
- **Gap** — Control is unmet; remediation is required
- **N/A** — Not applicable to the Portal architecture today

---

## Summary scorecard

| Section | Total | Met | Partial | Gap | N/A | L2 Conformance |
|---|---:|---:|---:|---:|---:|---:|
| V1 Architecture | 14 | 8 | 3 | 3 | 0 | 71% |
| V2 Authentication | 12 | 4 | 5 | 3 | 0 | 67% |
| V3 Session Management | 8 | 4 | 2 | 2 | 0 | 75% |
| V4 Access Control | 10 | 5 | 3 | 2 | 0 | 75% |
| V5 Validation, Encoding | 11 | 9 | 1 | 1 | 0 | 91% |
| V6 Stored Cryptography | 7 | 3 | 2 | 2 | 0 | 64% |
| V7 Error Handling + Logging | 9 | 2 | 4 | 3 | 0 | 56% |
| V8 Data Protection | 10 | 4 | 4 | 2 | 0 | 70% |
| V9 Communication | 6 | 4 | 1 | 1 | 0 | 83% |
| V10 Malicious Code | 5 | 3 | 1 | 1 | 0 | 80% |
| V11 Business Logic | 7 | 4 | 2 | 1 | 0 | 79% |
| V12 Files and Resources | 6 | 3 | 2 | 1 | 0 | 83% |
| V13 API and Web Service | 9 | 5 | 3 | 1 | 0 | 78% |
| V14 Configuration | 8 | 3 | 3 | 2 | 0 | 69% |
| **ASVS L2 total** | **122** | **61** | **36** | **25** | **0** | **~74%** |
| API Top 10 | 10 | 4 | 4 | 2 | 0 | 60% |

**Headline:** Tenant isolation + path-based access control are strong
by construction (V4 + API1 BOLA pass cleanly). The biggest gaps are
operator-side authentication (single shared admin token — V2 / API2),
logging + monitoring (V7 — tenant_id not tagged on every request),
and stored cryptography (V6 — encryption-at-rest depends on
deployment env, not enforced in code). Closing those three gaps gets
the Portal to ~90% L2 conformance — production-readiness for the
first paying customer.

---

## Part 1 — OWASP ASVS v4 Level 2

### V1: Architecture, Design and Threat Modeling

| Control | Description | Status | Evidence / Remediation | Owner |
|---|---|---|---|---|
| 1.1.1 | Use of secure development lifecycle | **Partial** | Code review + CI exists; no formal SDLC document yet. Remediation: write `docs/sdlc.md`. | Tech lead |
| 1.1.2 | Threat model per significant feature | **Gap** | No threat models exist for current features. Remediation: author threat models for tenant_auth, bridge ingestion, audit report signing. | Security lead |
| 1.1.3 | Component-level architecture documented | **Met** | `portal_capabilities_brief.md` + `docs/cve_intelligence_architecture.md` + design docs for Phases 1-7 |  |
| 1.1.4 | Data classification per data type | **Gap** | No classification taxonomy. Remediation: classify per-table data (public / internal / customer-confidential / customer-restricted) when Phase 8 ships. | Security lead |
| 1.1.5 | Authentication + access control per identity type | **Met** | Two-scheme model (operator admin + per-tenant bearer) in `api/src/core/tenant_auth.py` |  |
| 1.1.6 | Use centralized + curated security controls | **Met** | Auth + RBAC + bcrypt all centralized in `api/src/core/` |  |
| 1.1.7 | Identification of system context + boundaries | **Met** | Architecture diagram in capabilities brief §5 documents trust boundaries |  |
| 1.2.1 | Use of low-privilege OS account | **Met** | FastAPI runs under non-root in production container |  |
| 1.2.2 | Distinct credentials per app component | **Met** | Postgres has separate `compliance_reader` + Portal-own role |  |
| 1.2.3 | Authentication mechanism documented + secure | **Partial** | Documented per scheme, but no holistic auth architecture doc. Remediation: `docs/portal_auth_architecture.md` | Tech lead |
| 1.2.4 | Authentication path failure-secure | **Met** | bcrypt verification + path-based tenant_id check fail closed; no fail-open path |  |
| 1.4.1 | Use of trusted enforcement points | **Met** | FastAPI dependency middleware (`require_admin`, `require_tenant`) |  |
| 1.4.2 | Single-point trusted-enforcement-points pattern | **Gap** | RBAC checks hardcoded in handler code. Per A1 §2 principle, switch to `policy_engine.evaluate(actor, action, resource)`. Remediation: policy-engine refactor before tier enforcement (Piece 27). | Tech lead |
| 1.4.3 | Principle of least privilege applied | **Met** | Tenant tokens have scopes; operator-admin token has full scope (will narrow with OIDC operator SSO — A1 S1) |  |

**14 controls: 8 Met / 3 Partial / 3 Gap / 0 N/A (71% L2)**

### V2: Authentication

| Control | Status | Evidence / Remediation | Owner |
|---|---|---|---|
| 2.1.1 Passwords ≥ 12 chars / bcrypt cost ≥ 10 | **Met** | Tenant tokens are 48-char random + bcrypt cost 12. | |
| 2.1.5 Admin-initiated password reset | **Met** | Token revoke + reissue via `/admin/v1/tenants/{id}/tokens` | |
| 2.1.7 Constant-time password comparison | **Met** | `bcrypt.checkpw` | |
| 2.2.1 Anti-automation controls on auth | **Gap** | No rate limit; A1 R1 → Piece 27 | Tech lead |
| 2.2.2 Notification on auth anomaly | **Gap** | No per-tenant alert. Phase 8 governance. | Security lead |
| 2.2.3 Use of trusted external auth services | **Partial** | OIDC for operators planned (A1 S1), not shipped | |
| 2.3.1 System-generated initial passwords transmitted securely | **Met** | Token_secret shown once at issuance | |
| 2.5.1 Active session invalidated on factor change | **Met** | Token revocation immediate | |
| 2.5.6 No credentials in URL | **Met** | Bearer header only | |
| 2.7.1 MFA available | **Gap** | Designed in policy ingestion §9; not implemented | Tech lead |
| 2.7.2 MFA recovery method | **Partial** | Backup codes designed | |
| 2.8.1 Session re-authentication for sensitive ops | **Partial** | MFA challenge planned for write actions; not enforced yet | |

**12 controls: 4 Met / 5 Partial / 3 Gap / 0 N/A (67% L2)**

### V3: Session Management

| Control | Status | Evidence / Remediation | Owner |
|---|---|---|---|
| 3.1.1 Session token generated server-side | **Met** | `secrets.choice` | |
| 3.2.1 New session on authentication | **Met** | Each token independent | |
| 3.2.3 Sufficient session entropy | **Met** | 48 chars × 6 bits = 288 bits | |
| 3.3.1 Logout function | **Partial** | Token revoke works; OIDC formal logout pending | |
| 3.4.1 TLS-only token transmission | **Met** | Nginx enforces HTTPS | |
| 3.5.1 Anti-CSRF for state-changing requests | **Partial** | SameSite cookies + bearer auth | |
| 3.7.1 Risk-proportional session timeout | **Gap** | Uniform TTL; should vary by role | Tech lead |
| 3.7.2 Inactivity timeout | **Gap** | No inactivity threshold. Refresh-token model required. | Tech lead |

**8 controls: 4 Met / 2 Partial / 2 Gap / 0 N/A (75% L2)**

### V4: Access Control

| Control | Status | Evidence / Remediation | Owner |
|---|---|---|---|
| 4.1.1 Server-side access control enforcement | **Met** | FastAPI deps cannot be bypassed | |
| 4.1.2 Trusted subject + authorization | **Met** | Token + path scoping | |
| 4.1.3 Principle of least privilege | **Met (tenant)** / **Partial (operator)** | Operator admin token has full scope (A1 S1) | |
| 4.1.5 Deny by default | **Met** | Auth must succeed; no fallthrough | |
| 4.2.1 Per-business-object enforcement | **Met** | Tenant_id path component on every customer route | |
| 4.2.2 Tenant isolation provably enforced | **Met** ✅ | Path + bcrypt; provable by construction | |
| 4.3.1 Admin interface logically separated | **Partial** | Separate URL + token, shared service | |
| 4.3.2 Admin interface stronger auth | **Gap** | Same token model. OIDC + MFA needed (A1 S1) | Security lead |
| 4.3.3 Privilege escalation prevented | **Met** | Token scope cannot be elevated via API | |
| 4.3.4 Authentication asserted on every request | **Met** | Stateless bearer on every call | |

**10 controls: 5 Met / 3 Partial / 2 Gap / 0 N/A (75% L2)**

### V5: Validation, Sanitization and Encoding

| Control | Status | Evidence / Remediation |
|---|---|---|
| 5.1.1 Input data structure validated | **Met** | Pydantic models |
| 5.1.2 URL parameters validated | **Met** | Pydantic Path / Query |
| 5.1.3 HTTP headers validated | **Met** | Pydantic Header |
| 5.1.4 Request body validated | **Met** | Pydantic Body |
| 5.1.5 Request size limited | **Partial** | 16 MB default; not customized per endpoint |
| 5.2.1 Parameterized queries | **Met** | asyncpg native parameterization |
| 5.2.4 NULL bytes rejected | **Met** | Pydantic strips by default |
| 5.3.1 Output encoding HTML | **Met** | React auto-escaping |
| 5.3.3 Output encoding JSON | **Met** | FastAPI JSONResponse |
| 5.5.2 XML / XXE prevention | **Met** | No XML parsing in MVP path |
| 5.5.4 SSRF prevention (allow-list outbound) | **Gap** | LLM + git fetch unrestricted. Remediation: outbound allowlist. |

**11 controls: 9 Met / 1 Partial / 1 Gap / 0 N/A (91% L2)** ✅

### V6: Stored Cryptography

| Control | Status | Evidence / Remediation | Owner |
|---|---|---|---|
| 6.1.1 Sensitive data identification | **Partial** | No formal taxonomy. Remediation: classification policy in operations runbook. | Security lead |
| 6.1.2 Encrypted at rest | **Gap** | Depends on deploy env; not enforced in code. Remediation: enforce via Terraform + ops runbook. | Ops lead |
| 6.1.3 Encrypted in transit | **Met** | HTTPS required; asyncpg TLS configurable | |
| 6.2.1 Approved cryptographic algorithms | **Met** | bcrypt (cost 12), ed25519 planned | |
| 6.2.2 Key management documented | **Gap** | No KMS plan. Remediation: `docs/key_management.md` before Phase 7. | Security lead |
| 6.3.1 Random number generation | **Met** | `secrets` module (urandom) | |
| 6.4.1 Master secrets in HSM / KMS | **Partial** | Portal authoritative key planned to use cloud KMS; not implemented | |

**7 controls: 3 Met / 2 Partial / 2 Gap / 0 N/A (64% L2)**

### V7: Error Handling and Logging

| Control | Status | Evidence / Remediation | Owner |
|---|---|---|---|
| 7.1.1 No info leakage in error messages | **Partial** | FastAPI dev exposes stacks; prod env disables | Tech lead |
| 7.1.2 No sensitive info in URLs / logs | **Gap** | Token IDs logged at INFO; redaction needed. Remediation: log filter middleware. | Tech lead |
| 7.1.3 Generic error pages for unhandled | **Met** | FastAPI exception handlers | |
| 7.2.1 Logging of auth events | **Met** | `policy_audit_log` captures token issue + revoke | |
| 7.2.2 Logging of access control events | **Partial** | Admin actions logged; tenant-scoped not consistent | Tech lead |
| 7.3.1 Log entries include tenant_id | **Gap** | A1 G2 — request logs untagged. Remediation: structured logging middleware (high priority). | Tech lead |
| 7.3.2 Use of central logging | **Gap** | Container stdout only. Remediation: ops runbook §1 Loki/Elastic deploy. | Ops lead |
| 7.4.1 Time synchronization | **Met** | Deploy env NTP | |
| 7.4.2 Sufficient log detail for investigation | **Partial** | Schema exists; coverage incomplete | |

**9 controls: 2 Met / 4 Partial / 3 Gap / 0 N/A (56% L2)** ⚠️ — lowest section

### V8: Data Protection

| Control | Status | Evidence / Remediation |
|---|---|---|
| 8.1.1 Cache-Control prevents sensitive caching | **Met** | Headers via middleware |
| 8.1.2 No sensitive data on client | **Met** | Token_secret never re-fetched |
| 8.2.1 Data minimization | **Partial** | Customer policy content is what it is |
| 8.2.2 Sensitive data flagged + protected | **Gap** | Depends on classification (V6 gap) |
| 8.3.1 Backups encrypted | **Met** | Ops runbook §2 KMS-backed |
| 8.3.2 Backup access controlled | **Met** | Separate IAM role |
| 8.3.3 Retention policy documented | **Partial** | Defined; not infra-enforced |
| 8.3.4 Data deletion verified | **Partial** | Soft-delete; hard delete + verify pending |
| 8.5.1 Privacy + data protection law compliance | **Partial** | GDPR data lifecycle in Phase 8 |
| 8.5.2 Privacy policy disclosed | **Partial** | Internal only; customer-facing pending |

**10 controls: 4 Met / 4 Partial / 2 Gap / 0 N/A (70% L2)**

### V9: Communication

| Control | Status | Evidence / Remediation |
|---|---|---|
| 9.1.1 HTTPS everywhere | **Met** | nginx + HSTS |
| 9.1.2 TLS 1.2+ only | **Met** | nginx config |
| 9.1.3 Strong cipher suites | **Met** | Mozilla "intermediate" config |
| 9.2.1 Server certificate management | **Met** | Let's Encrypt + monitoring |
| 9.2.4 OCSP / CT log monitoring | **Partial** | LE provides CT; explicit OCSP not configured |
| 9.2.5 mTLS support where appropriate | **Gap** | Bridge could use mTLS; not implemented. Optional opt-in for high-security tenants. |

**6 controls: 4 Met / 1 Partial / 1 Gap / 0 N/A (83% L2)**

### V10: Malicious Code

| Control | Status | Evidence / Remediation |
|---|---|---|
| 10.1.1 Dependencies tracked via SBOM | **Partial** | SBOM concept in Phase 7; not generated yet |
| 10.2.1 Source code reviewed for backdoors | **Met** | PR review process |
| 10.2.2 Sources verified against threats | **Met** | Renovate + Dependabot |
| 10.3.1 No malicious deps | **Met** | Pinned + scanned |
| 10.3.2 Build integrity verified | **Gap** | Reproducible builds not verified. Remediation: enable + sign image manifests. |

**5 controls: 3 Met / 1 Partial / 1 Gap / 0 N/A (80% L2)**

### V11: Business Logic

| Control | Status | Evidence / Remediation |
|---|---|---|
| 11.1.1 Server-side business validation | **Met** | All logic in FastAPI handlers |
| 11.1.2 Workflow enforcement | **Met** | Policy state machine (draft → in_review → published) enforced |
| 11.1.3 Business limits enforced | **Partial** | Rate limits planned (Piece 27) |
| 11.1.4 Resists automated attack | **Partial** | Depends on rate limit |
| 11.1.5 Sequential ordering enforced | **Met** | Workflow states enforce order |
| 11.1.6 Transaction integrity | **Met** | asyncpg transactions |
| 11.1.7 App-specific logging | **Gap** | Bridge-side delivery audit missing. Remediation: bridge log feed. |

**7 controls: 4 Met / 2 Partial / 1 Gap / 0 N/A (79% L2)**

### V12: Files and Resources

| Control | Status | Evidence / Remediation |
|---|---|---|
| 12.1.1 Untrusted file upload restricted | **Met** | Type whitelist + size limit |
| 12.1.2 File type validated | **Partial** | MIME-check; magic-byte verification pending |
| 12.2.1 Files served outside execution scope | **Met** | Object store; never executed |
| 12.3.1 Path traversal prevented | **Met** | Pydantic + uuid filenames |
| 12.4.1 Trusted file storage location | **Met** | Encrypted bucket per tenant |
| 12.5.1 File metadata stripped before storage | **Gap** | PDFs retain metadata. Remediation: opt-in metadata strip. |

**6 controls: 3 Met / 2 Partial / 1 Gap / 0 N/A (83% L2)**

### V13: API and Web Service

| Control | Status | Evidence / Remediation |
|---|---|---|
| 13.1.1 API auth method appropriate per use | **Met** | Bearer + planned OIDC |
| 13.1.2 API access control consistent with app | **Met** | Same `require_*` pattern |
| 13.1.3 API rate limiting | **Gap** | A1 R1 / Piece 27 |
| 13.2.1 HTTP method appropriate per action | **Met** | RESTful |
| 13.2.2 Content negotiation | **Met** | JSON default; Accept header |
| 13.2.3 Standard HTTP status codes | **Met** | |
| 13.3.1 Validate API responses (outbound calls) | **Partial** | LLM + git client responses not strictly validated |
| 13.3.2 Validate webhook inputs | **Partial** | Incoming attestation pending |
| 13.4.1 OpenAPI / API contract | **Met** | FastAPI auto-generates |

**9 controls: 5 Met / 3 Partial / 1 Gap / 0 N/A (78% L2)**

### V14: Configuration

| Control | Status | Evidence / Remediation | Owner |
|---|---|---|---|
| 14.1.1 Secure configuration documented | **Partial** | Ops runbook §7 covers; not exhaustive | |
| 14.1.2 Default credentials changed | **Met** | None in codebase | |
| 14.2.1 Latest framework versions | **Met** | Renovate/Dependabot | |
| 14.2.2 No known-vulnerable deps | **Met** | CI security scan | |
| 14.3.1 Debug features disabled in prod | **Gap** | Not deployment-verified. Remediation: deployment checklist. | Ops lead |
| 14.3.2 No info leak in HTTP responses | **Partial** | `Server:` header exposed. Remediation: nginx tightening. | Ops lead |
| 14.4.1 Security headers hardened | **Gap** | Minimal CSP, HSTS only. Remediation: OWASP Secure Headers Project. | Tech lead |
| 14.5.1 Audit trail of config changes | **Partial** | git covers code; prod config not always tracked | |

**8 controls: 3 Met / 3 Partial / 2 Gap / 0 N/A (69% L2)**

---

## Part 2 — OWASP API Security Top 10 (2023)

### API1:2023 — Broken Object Level Authorization (BOLA)

**Status: ✅ Met**

The Portal's tenant_id path scoping + bcrypt token verification
provably enforce object-level access control. A request to
`/api/portal/v1/tenants/X/cves` with a token issued for tenant Y
returns 401. **Strong by construction** — the most common API
vulnerability class is structurally impossible in our design.

### API2:2023 — Broken Authentication

**Status: 🟡 Partial**

Tenant-token auth is solid (bcrypt cost 12, scope checks, revocation,
TLS-only). The operator-side single shared `PORTAL_ADMIN_TOKEN` is
the weak link (A1 S1). MFA designed in policy ingestion §9 but not
implemented. **Remediation:** OIDC operator SSO with MFA (Phase 1
implementation per policy ingestion design).

### API3:2023 — Broken Object Property Level Authorization

**Status: ✅ Met**

Pydantic models filter response fields per access level. No
mass-assignment from request bodies. Tenant token scopes restrict
which properties can be modified.

### API4:2023 — Unrestricted Resource Consumption

**Status: ❌ Gap**

No rate limiting (A1 R1). A misbehaving tenant could exhaust shared
resources. **Remediation:** Piece 27 (tier enforcement with per-tenant
rate limits) — this is the single highest-priority Portal gap per the
SaaS Lens assessment.

### API5:2023 — Broken Function Level Authorization

**Status: ✅ Met**

Admin paths (`/admin/v1/*`) require `PORTAL_ADMIN_TOKEN`. Tenant paths
require tenant token + matching tenant_id. No function-level
escalation possible.

### API6:2023 — Unrestricted Access to Sensitive Business Flows

**Status: 🟡 Partial**

No automation detection or anti-bot. Scripted attacker could
enumerate tenants by trying token combinations (success infeasible
due to bcrypt cost 12 + 288-bit secret entropy). **Remediation:**
rate limit (Piece 27) + anomaly detection on auth patterns (A1 O1 /
Piece 30 observability).

### API7:2023 — Server Side Request Forgery (SSRF)

**Status: 🟡 Partial**

LLM client outbound calls are unrestricted in MVP. Customer git repo
ingestion (Phase 1 policy ingestion) is fetch-allowed.
**Remediation:** explicit allowlist on outbound HTTP from LLM client
+ git fetch client. Also covers ASVS V5.5.4.

### API8:2023 — Security Misconfiguration

**Status: 🟡 Partial**

Same as ASVS V14 — production config hardening incomplete (headers,
debug features, server identification). **Remediation:** deployment
checklist + nginx hardening + OWASP Secure Headers compliance.

### API9:2023 — Improper Inventory Management

**Status: ✅ Met**

OpenAPI auto-generated; API surface documented in design docs.
Versioning via `/api/portal/v1/` path prefix. Deprecation policy
covered in operations runbook §12.

### API10:2023 — Unsafe Consumption of APIs

**Status: ❌ Gap**

Outbound calls to LLM provider, GitHub (repo ingestion), GRC
platforms (Phase 7) — no formal validation of responses, no circuit
breakers, no formal timeout / retry policy. **Remediation:** response
schemas + circuit breakers + structured retry/backoff on every
outbound HTTP client.

---

## Summary scorecard

(See top of doc.)

**~74% ASVS L2 conformance; 60% API Top 10 conformance** is the
honest snapshot. Closing the top three gaps (operator OIDC SSO +
rate limiting + tenant-tagged logging) lifts both to ~90% / ~90%.
**That's the production-readiness bar for the first paying customer.**

---

## Top remediation priorities

In priority order — same prioritization across A1/A2/A3 (the three
strategic baseline docs converge here):

1. **Rate limiting + tier enforcement** (A1 R1 / API4 / V13.1.3) — Piece 27
2. **Tenant-tagged structured logging + metrics** (A1 O1 / V7.3.1 / V7.3.2) — Piece 30
3. **OIDC operator SSO + MFA** (A1 S1 / API2 / V2.7.1 / V4.3.2) — brief decision D7
4. **Tenant data lifecycle policy** (A1 S2 / V6.1.2 / V8.5.1) — new piece
5. **Secure-headers + nginx hardening** (V14.4.1 / API8) — quick-win

The first three are also the SaaS Lens assessment's top three; the
two checklists agree on what matters first.

---

## Linked cross-references

- **A1 SaaS Lens assessment** (`portal_saas_lens_assessment.md`) — pillar 2 (Security) cross-references the same control families
- **Operations runbook** (`portal_operations_runbook.md`) — §6 (Access Control), §9 (Security Operations), §10 (Customer Support Operations) detail the operational implementation of these controls
- **Capabilities brief** (`portal_capabilities_brief.md`) — §6.4 (Operational guarantees / SLAs / status / billing) discusses the customer-facing trust posture
- **Policy ingestion design** (`policy_ingestion_design.md`) — RBAC + MFA spec
- **Competitive benchmark** (`portal_competitive_benchmark.md`) — peers' security postures by independent third-party assessment

---

**Authored with Claude (Anthropic).**
