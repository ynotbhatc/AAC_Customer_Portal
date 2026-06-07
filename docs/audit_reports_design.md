# AAC Customer Portal — Audit Reports Design

**Audience:** Internal planning — engineering, product, security review, customer success, compliance / audit subject-matter reviews.
**Purpose:** Design specification for **Phase 7** of the compliance
loop — the audit-ready report generator. Companion to
`policy_ingestion_design.md` (Phases 1-4), `remediation_generator_design.md`
(Phase 5), and `golden_image_generator_design.md` (Phase 6). Defines
how the measurable evidence from Phases 1-6 is consolidated into
auditor-facing narratives, signed, and delivered.
**Drafted:** 2026-06-02
**Version:** v1.0

## Revision history

| Version | Date | Change |
|---|---|---|
| v1.0 | 2026-06-02 | Initial design. Per-framework report templates (SOC 2 Service Organization Description, ISO 27001 Statement of Applicability + audit evidence, PCI-DSS Report on Compliance excerpts, HIPAA Security Rule §164.308 evidence). Evidence aggregation engine. Three output formats (DOCX, signed PDF, signed JSON for direct GRC platform ingestion). Customer review and sign-off workflow. Direct-to-auditor delivery options. Independent auditor verification tooling (Portal-account-free). |

---

## 0. Guiding principle — measurable first, then narrative

> **Audit reports are the consolidation of measurable evidence.**
> Every claim in a Portal-generated report links back to a signed
> artifact: a policy SHA, a Rego file SHA, an assessment result row,
> a build attestation, a remediation outcome. No claim is "trust
> us"; every claim is verifiable by an auditor with no Portal account.

This principle drives three non-negotiable design properties:

1. **No new evidence is created in Phase 7.** All evidence already
   exists in `compliance_results`, `policy_audit_log`,
   `customer_remediation_runs`, `customer_golden_image_builds`, and
   the per-tenant git buckets. Phase 7 *aggregates and narrates*
   what's already there.

2. **The report itself is signed.** A Portal authoritative signature
   on the report + per-evidence-item signatures inside it. Tampering
   is detectable by the auditor independently.

3. **The auditor doesn't need a Portal account to verify.** A small
   CLI tool + a web verifier on the public Portal site lets any
   auditor confirm: "yes, this is a genuine Portal-issued report;
   yes, the evidence references resolve to actual evidence; yes, the
   chain of custody is unbroken."

The administrative governance work (Tier 1 in policy ingestion §23 /
Phase 8) is not part of audit reports for MVP. When Phase 8 ships,
governance attestations (periodic reviews completed, exceptions
approved, risks linked) become additional sections in the report.

---

## 1. Where this sits in the compliance loop

```
   policy_ingestion → IR  ──────────────────────────────────────┐
                                                                 │
   ┌─── Rego ──── AAC live assessment ────► compliance_results ──┤
   │       (Phase 1-4)                                           │
   │                                                             │
   ├─── Remediation ── AAP runs ──► customer_remediation_runs ───┤
   │       (Phase 5)                                             │
   │                                                             │
   └─── Golden image ── customer CI ──► customer_golden_image_builds
            (Phase 6)                                            │
                                                                 │
                                                                 ▼
                                                ┌────────────────────────────┐
                                                │ Phase 7 — audit-reports    │
                                                │  (THIS DOC)                │
                                                │                            │
                                                │  Evidence aggregator       │
                                                │   • policy lineage         │
                                                │   • live posture window    │
                                                │   • gap history + fixes    │
                                                │   • image attestations     │
                                                │   • chain of custody       │
                                                │   • bundle history         │
                                                │   • operator certs (SOC 2  │
                                                │     of the Portal itself)  │
                                                │                            │
                                                │  Per-framework template    │
                                                │   • SOC 2 Type II SOD      │
                                                │   • ISO 27001 SoA          │
                                                │   • PCI-DSS RoC excerpts   │
                                                │   • HIPAA evidence         │
                                                │   • NIST 800-53 ATO        │
                                                │                            │
                                                │  Signed output             │
                                                │   • DOCX (human)           │
                                                │   • signed PDF (human)     │
                                                │   • signed JSON (machine)  │
                                                │                            │
                                                │  Direct delivery           │
                                                │   • download for customer  │
                                                │   • S3/SFTP to auditor     │
                                                │   • GRC API upload         │
                                                │     (Drata, Vanta, etc.)   │
                                                └─────────────┬──────────────┘
                                                              │
                                                              ▼
                                                ┌────────────────────────────┐
                                                │  Auditor                   │
                                                │   • opens report in their  │
                                                │     audit platform         │
                                                │   • verifies signatures    │
                                                │     via Portal's public    │
                                                │     web verifier (no       │
                                                │     account needed)        │
                                                │   • drills into evidence   │
                                                │     via signed links       │
                                                └────────────────────────────┘
```

The Phase 7 generator is the **narrative aggregator** — it doesn't
produce evidence; it produces the story (with citations) that an
auditor can directly accept.

---

## 2. The contract — what "audit-ready" means

A report meets the audit-ready bar when it satisfies five
properties:

### 2.1 Citation-backed claims

Every assertion in the report has at least one citation pointing to
a signed artifact:

```
"Acme's Password Standard v3.2 was published on 2026-04-12 by
 jane.smith@acme.com [^policy-sha], reviewed quarterly per the
 customer's process [^review-log], and applied across 87 systems
 [^assessment-results]."

[^policy-sha]: customer_policies.id=abc-123 sha256=...
[^review-log]: policy_audit_log entries 2026-04-12 to 2026-06-12
[^assessment-results]: compliance_results.framework='cis_rhel9' WHERE customer_policy_id=abc-123 between 2026-04-01 and 2026-06-30
```

The footnote is a signed reference, not prose. The Portal can pull
the underlying record up on demand for the auditor.

### 2.2 Time-bounded scope

Every report is for a specific time window (typically a quarter or
audit period). All claims within the report are scoped to that
window. The window is fixed at generation time and embedded in the
report header.

### 2.3 Authoritative signing

The Portal signs the full report with its authoritative key. Anyone
with the Portal's public key can verify:

- The report was generated by the Portal (signature validates)
- The report has not been tampered with (hash matches the signed digest)
- The report was generated for the specific time window claimed (window is part of the signed material)

### 2.4 Chain-of-custody for every actor

Every authored / reviewed / approved / published event in the report
includes:

- Actor identity (MFA-asserted at the time of action)
- Timestamp (Portal server time, signed)
- Action type and target
- IP / session metadata where relevant

This is the "who did what when" trail auditors universally require.

### 2.5 Independent verifiability

An auditor with the report + the Portal's public key (published
permanently on the Portal's trust page) can verify the report's
authenticity using:

- A small open-source CLI tool (`portal-verify`) we ship
- A web verifier on `verify.aac-portal.example` (no account needed)

The auditor never needs to log into the Portal to trust what they're
holding.

---

## 3. Per-framework report templates

The Portal ships templates for each major compliance framework.
Customer chooses the template at report generation time; the same
underlying evidence is reshaped into the framework's expected
narrative.

### 3.1 SOC 2 Type II — Service Organization Description (SOD)

The auditor's primary input for the customer's annual SOC 2 report.
Includes:

- Service description (services in scope; customer-supplied; Portal pre-populates from tenant metadata)
- System description (what's running; from `tenant_inventory_catalog`)
- Trust Services Criteria coverage analysis (from `policy_ingestion_design.md` §24.1)
- Control activities matrix per criterion (CC1-CC9, A, C, PI, P), with citation footnotes to specific Rego files + assessment results
- Sub-service organizations (Portal itself; vendor list if Tier 1 governance ships)
- Complementary user entity controls (boilerplate; customer reviews)
- Operating-effectiveness evidence per control (assessment results over the audit window)

### 3.2 ISO 27001:2022 — Statement of Applicability (SoA) + audit evidence

- Statement of Applicability table (93 Annex A controls; included / excluded with justification)
- Control implementation evidence per included control (Rego sha + assessment outcomes)
- Risk register (if Tier 1 ships)
- Internal audit results (the Portal's own assessment cycle counts as the internal audit)
- Management review records (from `policy_audit_log` for tenant_user with `role = account_owner` actions)

### 3.3 PCI-DSS v4.0 — Report on Compliance (RoC) excerpts

PCI-DSS has 12 requirements with ~300 sub-controls. The Portal
generates the technology-state portions (most of Req 1-4 + Req 6 +
Req 8 + Req 10), with explicit "out-of-scope" markers for the
administrative portions (Req 9 physical, Req 12 InfoSec policy
governance).

### 3.4 HIPAA Security Rule §164.308 — administrative + technical safeguards

Maps Portal evidence to HIPAA's 9 administrative + 5 technical
safeguards. Strong on technical (encryption status, audit log
configuration, access controls); explicit "see customer's HRIS for
workforce security" for administrative.

### 3.5 NIST 800-53 / FedRAMP — Authorization Package (ATO) evidence

FedRAMP requires an Authorization Package — the 800-53 control
implementation summary + System Security Plan (SSP) excerpts. The
Portal pre-populates the technology-state controls (CM, AC, AU, IA,
SC, SI families) and marks the personnel/physical families as
out-of-scope.

### 3.6 Custom evidence bundle

When the auditor asks for evidence in a non-standard format,
customers can build a custom query:

- Pick time window
- Pick policies to include
- Pick output fields
- Generate signed JSON evidence bundle

This is the escape hatch for the "auditor wants something we didn't
anticipate" case.

---

## 4. Evidence aggregation engine

The core service that turns time-windowed queries into citation-backed
narrative. Implemented as a Python module that runs against the
existing Portal database.

### 4.1 Aggregation pipeline

```python
def aggregate_evidence(tenant_id, framework, window_start, window_end):
    evidence = EvidenceBundle(
        tenant_id=tenant_id,
        framework=framework,
        window={"start": window_start, "end": window_end},
    )

    # Section 1: Policy lineage (every active + archived policy in scope)
    evidence.policies = query_customer_policies_in_window(...)
        # → list of (policy_id, name, version, owner, prose_doc_sha,
        #            ir_sha, generated_rego_shas, published_at, archived_at)

    # Section 2: Live posture (assessment results over the window)
    evidence.posture = query_assessment_history(...)
        # → time-series of compliance % per policy per control class

    # Section 3: Gap history (gaps detected + their disposition)
    evidence.gaps = query_gap_history(...)
        # → list of (gap_detected_at, control_id, hosts_affected,
        #            mitigation_run_id, mitigation_outcome, post_mitigation_state)

    # Section 4: Golden image attestations
    evidence.golden_images = query_image_builds_in_window(...)
        # → list of (image_sha, policy_version_set, attestation_sha,
        #            assessed_compliance_pct)

    # Section 5: Chain of custody
    evidence.audit_log = query_policy_audit_log(...)
        # → all author/review/approve/publish events with MFA-asserted actor

    # Section 6: Bundle delivery history
    evidence.bundles = query_bundle_history(...)
        # → which bundles were pulled by the customer's AAC bridge,
        #    bridge-side verification result, OPA load timestamp

    # Section 7: Portal-side operator attestations
    evidence.operator = query_operator_attestations(...)
        # → Portal's own SOC 2, pentest, SBOM, key-rotation log

    return evidence
```

Each query returns a stream of references — not raw data — so the
generated report can include signed citations without bloating the
output document. The raw evidence stays in the source tables; the
report includes pointers that the auditor can resolve.

### 4.2 Signed citation format

Each citation in the report references signed evidence:

```yaml
# example citation embedded in DOCX comment / PDF link / JSON field
citation:
  type: assessment_result
  id: compliance_results.id=12345
  signed_ref_url: https://portal.aac/v1/tenants/<tid>/evidence/12345?sig=...
  sha256: <hash of the row content>
  signed_by: portal_authoritative_key_v1
  signed_at: 2026-06-12T14:30:00Z
```

The signature is over the canonical-form of the underlying row +
some metadata (tenant_id, timestamp, key fingerprint). The auditor's
verifier resolves the URL, fetches the row, recomputes the hash,
checks the signature.

### 4.3 Operator attestation block

The Portal's own compliance posture is a section in every report.
It's the "trust the Portal itself" evidence package:

| Attestation | What it says |
|---|---|
| Portal SOC 2 Type II report reference | Portal-side certification (independent auditor) |
| Penetration test report SHA + date | Most recent pentest of the Portal |
| SBOM for the Portal release | Dependency inventory |
| Key rotation log | When the Portal's signing keys were last rotated |
| Bundle signing key fingerprint | Public key for the Portal authoritative key (auditor can pin) |
| Tenant data lifecycle policy SHA | Portal's own retention + deletion policy |

This block answers the auditor's natural question: "if I'm trusting
the Portal to attest to all this evidence, why should I trust the
Portal?"

---

## 5. Output formats

### 5.1 DOCX (human-readable)

Generated via the existing `document_production.md` convention —
`python-docx` with the same styling as the other portal docs.
Sections per the framework template (§3). Citations embedded as
comments / footnotes with hyperlinks to signed evidence URLs.

Used for: customer's own internal review; printed reference for the audit.

### 5.2 Signed PDF (human-readable, tamper-evident)

The DOCX rendered to PDF (Chrome-headless), then sealed:

- PDF/A archival format
- Embedded XML metadata block with the Portal authoritative signature
- Signature is over the PDF's raw byte stream (no PDF-internal signing — that's tied to PDF readers and we want format-agnostic verification)

Used for: hand to the auditor; print without losing tamper-evidence.

### 5.3 Signed JSON (machine-readable, GRC ingestion)

The full report as in-toto-style structured JSON:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "audit-report", "digest": {"sha256": "<report_content_sha>"}}
  ],
  "predicateType": "https://portal.aac/audit-report/v1",
  "predicate": {
    "framework": "soc2_type_ii",
    "tenant": {...tenant metadata...},
    "window": {"start": "...", "end": "..."},
    "sections": {
      "policies": [...],
      "posture": [...],
      "gaps": [...],
      "golden_images": [...],
      "audit_log": [...],
      "bundles": [...],
      "operator_attestations": {...}
    }
  },
  "portal_signature": "...ed25519 over canonical JSON..."
}
```

Used for: direct upload into the auditor's evidence platform
(Drata Audit Hub, Vanta Audit Center, OneTrust, AuditBoard,
LogicGate, etc.). The platform can parse the JSON, ingest each
section, and link evidence URLs directly into the auditor's
workflow.

---

## 6. Signing and verification

### 6.1 Signing scheme

- **Algorithm**: ed25519 (modern, fast, supported in all major
  cryptography libraries)
- **Key**: Portal authoritative signing key, rotated annually,
  public key published on `verify.aac-portal.example` (HTTPS-pinned,
  HPKP-style fingerprint distributed independently)
- **Canonical-form**: All signed payloads are JCS-canonicalized
  (RFC 8785) before signing to defeat re-ordering attacks
- **Envelope format**: in-toto v0.9 (SLSA standard)

### 6.2 Independent verification path

**The auditor needs no Portal account to verify.** Three options:

1. **CLI tool** (`portal-verify`):
   ```
   $ portal-verify --report acme-soc2-q2-2026.json
   ✓ Report signature valid (key: portal_v1, fingerprint: ...)
   ✓ Window: 2026-04-01 to 2026-06-30
   ✓ 247 citations resolved + verified
   ✓ Chain of custody complete; no gaps
   Report verifies authentic and untampered.
   ```
   Open-sourced under Apache 2.0 so auditors can audit it.

2. **Web verifier**: `verify.aac-portal.example`. Upload a PDF or
   JSON, paste a public key fingerprint, get a green / red verdict
   with citations. No account needed.

3. **Third-party verifier**: We submit the verifier source to
   sigstore-style transparency logs so independent auditors can
   verify the verifier itself.

### 6.3 What gets signed

| Item | What the signature attests |
|---|---|
| Report envelope | The full report content + window + tenant + framework |
| Each citation reference | The signed URL + sha of the underlying evidence |
| Each evidence row in the source tables | The row content (signed at insert time, not at report time) |

The chain: report signature → citation signatures → evidence-row
signatures. Each layer is independently verifiable.

---

## 7. Delivery options

### 7.1 Customer download

Default. Customer downloads from the Portal dashboard. Three formats
available simultaneously (DOCX, signed PDF, signed JSON).

### 7.2 Direct-to-auditor signed link

Customer can generate a one-time-use signed link delivered direct to
the auditor's email. The link expires after a configurable window
(default 14 days); once consumed, the link is invalid.

Useful for: customers who don't want intermediaries handling audit
material (e.g., FedRAMP customers passing data to a 3PAO).

### 7.3 Direct upload to GRC platforms

The Portal integrates with major GRC platforms to push the signed
JSON report into the auditor's queue. Customer authorizes the
integration once; report uploads happen with a single click.

| Platform | Integration |
|---|---|
| Drata | Audit Hub API |
| Vanta | Vanta API + Audit Center |
| OneTrust | OneTrust Audit Management API |
| AuditBoard | RegFile API |
| LogicGate | Risk Cloud integration |
| Sigstore Rekor | Transparency-log entry (for customers who want public attestation) |

Each integration is implemented as an adapter behind a `DeliveryProvider`
interface (per the §2 extensibility principle in policy ingestion
design — we don't hardcode any specific GRC platform).

### 7.4 Air-gap delivery

For air-gapped customers, the signed bundle is exported out-of-band
(SFTP / DVD / signed envelope) per their pre-arranged transport.
Same signing format; different delivery transport.

---

## 8. Auditor-side verification tooling

### 8.1 The CLI tool

`portal-verify` — open-source under Apache 2.0 — written in Go
(small binary, no runtime deps). Verifies:

```
$ portal-verify --report acme-soc2-q2-2026.json --resolve-evidence
✓ Report signature valid (key: portal_v1, fingerprint: ...)
✓ Window: 2026-04-01 to 2026-06-30
✓ 247 citations resolved + verified
✓ Chain of custody complete; no gaps

Per-section:
  Policies in scope:                   23 (12 published + 11 archived during window)
  Assessments run:                  8,432 (compliance % avg 94.7%)
  Gaps detected + closed:              17 (mean time to close: 4h 22m)
  Golden images built:                  9 (all with valid attestations)
  Chain of custody events:          1,287 (all MFA-asserted)
  Bundles delivered:                  124 (all bridge-verified)

Report verifies authentic and untampered.
```

The tool is published to:
- GitHub releases (multi-platform binaries)
- Homebrew (`brew install portal-verify`)
- Container registry (`docker pull portal/verify`)
- sigstore Rekor (transparency log entry per release)

### 8.2 The web verifier

Hosted on `verify.aac-portal.example` (HTTPS-pinned, separate
domain from the main Portal so it stays available even if the
Portal is). Drag-and-drop a report file; get a verdict.

No account needed. No data retained server-side (verifier processes
in-browser via WebAssembly where possible).

---

## 9. Customer review and sign-off

Generated reports go through the same review-and-approve pattern as
policies, remediation, and golden images:

1. Customer triggers generation (parameters: framework, window, scope)
2. Aggregation runs (typically <2 minutes for an enterprise-scale tenant)
3. Notification to Account Owner + Compliance Officer (if configured)
4. Owner opens review UI:
   - Section-by-section preview
   - Evidence drill-down per claim
   - Annotation capability (Owner can add notes that travel with the report)
   - Export preview (DOCX / PDF render preview, JSON tree view)
5. Owner approves → Portal signs + makes available for delivery
6. Audit log captures: who generated, who reviewed, when, signature key fingerprint

### 9.1 Customer signature on the report

The customer also signs the report (in addition to the Portal's
signature) to attest "this is my official audit submission."

- Customer signing uses the Account Owner's MFA-verified identity
- The customer signature wraps the Portal's signature in an envelope
  (so the report carries both)
- Auditor verifies both signatures via the independent tooling

This is the customer's accountability layer — "I, jane.smith@acme.com,
on 2026-07-01 at 14:22 UTC after MFA verification, attest this
report is the official Q2 2026 audit evidence for Acme Corp."

---

## 10. Data model additions

Extending the existing Phase 1-6 models:

### `audit_report_templates`

Shared library — the per-framework report templates.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `framework_key` | text | `soc2_type_ii`, `iso27001_2022`, `pci_dss_v4`, `hipaa_security`, `nist_800_53`, `custom` |
| `display_name` | text | |
| `template_body` | text | Jinja-style template for the DOCX + JSON sections |
| `version` | text | Template version (bumped on framework spec changes) |
| `out_of_scope_sections` | text[] | What this template explicitly marks as out-of-scope |

### `customer_audit_reports`

Per-tenant generated reports.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | FK |
| `template_id` | uuid | FK → audit_report_templates |
| `window_start` | timestamptz | |
| `window_end` | timestamptz | |
| `scope_policies` | uuid[] | Customer policies included; nullable means "all in scope for framework" |
| `generated_at` | timestamptz | |
| `generated_by_user_id` | uuid | FK |
| `customer_signed_at` | timestamptz | nullable until customer signs |
| `customer_signed_by_user_id` | uuid | nullable |
| `customer_signature` | text | nullable |
| `portal_signed_at` | timestamptz | When Portal signed (after customer review approval) |
| `portal_signature` | text | The authoritative Portal signature |
| `portal_key_fingerprint` | text | Which Portal key was used (for rotation tracking) |
| `docx_storage_key` | text | Object-store key |
| `pdf_storage_key` | text | |
| `json_storage_key` | text | |
| `evidence_count` | int | Number of citations resolved |
| `status` | enum | `draft`, `under_review`, `customer_signed`, `delivered`, `archived` |

### `report_delivery_events`

Per-delivery log.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `customer_audit_report_id` | uuid | FK |
| `delivery_channel` | enum | `download`, `direct_signed_link`, `drata_api`, `vanta_api`, `onetrust_api`, `auditboard_api`, `logicgate_api`, `sftp`, `email`, `air_gap_export` |
| `recipient` | text | email / URL / SFTP host etc. |
| `delivered_at` | timestamptz | |
| `delivery_status` | enum | `pending`, `succeeded`, `failed`, `revoked` |
| `recipient_signed_receipt` | text | nullable — for delivery channels that support read-receipt signing |

---

## 11. API surface (new endpoints)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/portal/v1/tenants/{id}/audit-reports/templates` | List available framework templates |
| POST | `/api/portal/v1/tenants/{id}/audit-reports/generate` | Trigger generation: framework + window + scope |
| GET | `/api/portal/v1/tenants/{id}/audit-reports` | List generated reports |
| GET | `/api/portal/v1/tenants/{id}/audit-reports/{id}` | Detail view: status, sections preview, signatures |
| POST | `/api/portal/v1/tenants/{id}/audit-reports/{id}/customer-sign` | Customer signs (with MFA challenge) |
| POST | `/api/portal/v1/tenants/{id}/audit-reports/{id}/portal-sign` | Operator-side seal after customer signs |
| GET | `/api/portal/v1/tenants/{id}/audit-reports/{id}/download/{format}` | Download docx / pdf / json |
| POST | `/api/portal/v1/tenants/{id}/audit-reports/{id}/deliver` | Trigger delivery via configured channel |
| GET | `/api/portal/v1/tenants/{id}/audit-reports/{id}/deliveries` | Per-delivery audit trail |
| POST | `/api/portal/v1/tenants/{id}/evidence/{evidence_id}/resolve` | Resolve a signed citation reference |

### Public verifier endpoints (no auth)

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/portal-trust.json` | Trust manifest: current public keys, certificate chain, attestation policy |
| POST | `/api/verify/v1/report` | Public verifier endpoint — accepts a report payload + returns verdict |
| GET | `/api/verify/v1/keys` | Published public keys + rotation history |

---

## 12. Frontend pages

### Customer-facing

| Route | Purpose |
|---|---|
| `/audit-reports` | List + status + recent delivery activity |
| `/audit-reports/new` | Generation wizard: pick framework + window + scope |
| `/audit-reports/{id}` | Detail: section preview, evidence drill-down, signatures, delivery options |
| `/audit-reports/{id}/review` | Owner review screen with annotation capability |
| `/audit-reports/{id}/sign` | Customer sign-off with MFA challenge |
| `/audit-reports/{id}/deliver` | Delivery channel selection + recipient configuration |

### Public-facing (no auth)

| Route | Purpose |
|---|---|
| `verify.aac-portal.example` | Web verifier (drag-drop or paste) |
| `verify.aac-portal.example/keys` | Published public keys + fingerprints |
| `verify.aac-portal.example/cli` | Download the `portal-verify` CLI tool |
| `verify.aac-portal.example/docs` | Auditor's guide to using the verifier |

---

## 13. Failure modes

| Failure | Detection | Response |
|---|---|---|
| Evidence aggregation finds gaps in the chain (e.g., missing audit log entries) | During §4 aggregation | Generation fails with explicit gap report; customer can't sign until reconciled |
| Customer signing key revoked / expired during review | At sign step | Re-MFA + re-sign workflow; old signature recorded as superseded |
| Portal signing key rotated mid-generation | At Portal sign step | Generate with the new key; old key fingerprint retained in audit log |
| Delivery channel fails (e.g., Drata API down) | Delivery attempt | Mark delivery `failed`; retry per backoff; customer alerted; alternative channel offered |
| Auditor reports a citation can't be resolved | Aggregator-side issue | SEV-2 Portal incident; investigate; signed addendum may be required |
| Portal-side data tampering detected | Verifier check fails on customer's audit | All-hands stop-the-line; investigate; trust-rebuild plan |

---

## 14. Open questions (tweak as we go)

| # | Question | Default for MVP |
|---|---|---|
| 1 | Which frameworks ship templates in MVP? | **SOC 2 Type II + ISO 27001 + PCI-DSS** — the three most-asked. HIPAA + NIST 800-53 + FedRAMP in Phase 7.5. |
| 2 | Customer's own GRC platform integrations — which one(s) ship first? | **Drata + Vanta** — highest combined market share in our target buyer profile. OneTrust + AuditBoard in 7.5. |
| 3 | Signed citation URL retention — what's the SLA? | **7 years** from report generation; long enough for SOX / HIPAA. Customer Premium tier can extend. |
| 4 | When the auditor resolves a signed citation, do we log it? | **Yes**, with delivery_event records — useful for the customer to know the auditor is digging in. Optional opt-out for sensitive engagements. |
| 5 | Custom evidence bundles — should we LLM-assist the report narrative? | **No for MVP** — template-driven only. LLM narrative summarization is post-MVP. |
| 6 | Key rotation cadence | **Annual** rotation; old keys retained for verification of historic reports |
| 7 | Auditor verifier CLI — what platforms (binaries)? | **Linux + macOS + Windows** for MVP; web verifier covers everything else |
| 8 | Should the report include cost-of-compliance numbers? (Tech debt heat map data) | **Optional opt-in section** — useful for management presentations alongside audit submissions |
| 9 | Multi-tenant audit reports (parent organization spans multiple tenants) | **Phase 7.5** — needs hierarchical tenancy work |
| 10 | Should we offer "audit prep simulation" — a dry-run mode showing what an auditor would see? | **Yes**, as a draft/test mode of the same generator. Customer can iterate on coverage before formal generation. |

---

## 15. Phased implementation plan

**Phase 7** of the policy ingestion phased plan. Two sprints,
**after Phases 5 + 6 ship** (because reports cite remediation +
golden image evidence).

### Sprint 13 — generator + templates

1. New tables: `audit_report_templates`, `customer_audit_reports`, `report_delivery_events`
2. Three framework templates (SOC 2, ISO 27001, PCI-DSS) — DOCX + JSON renderers
3. Evidence aggregation engine (§4) with signed citation production
4. Portal signing service (key management, rotation, in-toto envelope)
5. Customer + Portal signature workflow with MFA on customer-sign
6. DOCX + signed PDF + signed JSON output generators

### Sprint 14 — verification + delivery + UI

7. Frontend `/audit-reports` pages (list, generate, review, sign, deliver)
8. Public verifier: web app on `verify.aac-portal.example` + `portal-verify` CLI tool
9. Delivery adapters for Drata API + Vanta API
10. Trust manifest publication (`/.well-known/portal-trust.json`)
11. End-to-end soak test: pilot customer generates a SOC 2 report, signs it, delivers to a sandbox Drata instance, the test auditor verifies via the public verifier

---

## 16. References

### Builds on / depends on

- `policy_ingestion_design.md` v1.3 — Phase 1-4 evidence sources
- `remediation_generator_design.md` v1.0 — Phase 5 evidence sources
- `golden_image_generator_design.md` v1.0 — Phase 6 evidence sources
- `portal_capabilities_brief.md` §6.3 (audit evidence collection) + Piece 19 (audit evidence delivery) + Piece 26 (audit certification)
- AAC task #45 (OPA bundle mode) — for the bundle history section of reports

### Standards adopted

- **in-toto v0.9** — attestation envelope format (same as Phase 6)
- **SLSA v1.0** — supply-chain integrity model
- **JCS / RFC 8785** — JSON canonicalization for signing
- **PDF/A-3** — archival PDF format
- **TUF** — trust manifest pattern for public-key distribution

### Framework spec references

- **SOC 2 Type II** — AICPA Trust Services Criteria
- **ISO/IEC 27001:2022** — Annex A controls
- **PCI-DSS v4.0** — Payment Card Industry Data Security Standard
- **HIPAA Security Rule §164.308 / §164.312** — Administrative + Technical Safeguards
- **NIST SP 800-53 Rev 5** — Federal control catalog
- **FedRAMP** — Authorization Package format

### Industry context

- **Drata Audit Hub** — leading audit evidence platform for SOC 2 / ISO 27001
- **Vanta Audit Center** — same space; second largest market share
- **OneTrust Audit Management** — enterprise-tier; broader GRC scope
- **AuditBoard RegFile** — enterprise audit automation
- **Sigstore Rekor** — transparency-log model for public attestations

---

**Authored with Claude (Anthropic).**
