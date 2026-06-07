# AAC Customer Portal — Capabilities & Focus

**Audience:** Internal — AAC platform engineers, solution engineers, product, sales enablement, leadership.
**Purpose:** Shared mental model of what the Portal is, what it offers customers, how it integrates with AAC, and where it's headed.
**Drafted:** 2026-06-02
**Version:** v2.1

## Revision history

| Version | Date | Change |
|---|---|---|
| v1.0 | 2026-06-02 | Initial draft — CVE-Intelligence-centric framing |
| v2.0 | 2026-06-02 | Reframed: Portal is a **compliance-as-a-service hub**; CVE Intelligence is one product among several. Added SLAs, policy injection, compliance-framework enrollment, audit evidence, multi-framework reporting, IoC sharing as planned features. Feature inventory moved to §1 per user request. |
| v2.1 | 2026-06-02 | Added seven roadmap pieces surfaced by user's portal-description email — customer-specific policy repo ingestion, "backup → patch → validate" normalized workflow contract, **SaaS / Cloud Services SLA monitoring** (new dimension), inventory-driven automatic enrollment, baselining outputs, technical-debt heat map UI, audit *certification* (signed authoritative bundles, distinct from evidence delivery). Each tied to an email function; status table extended (§11.2). |

---

> For deeper architectural detail, see:
> - `docs/architecture.md` — original compliance-only architecture
> - `docs/cve_intelligence_architecture.md` — CVE feature architecture
>
> This brief is the executive-and-engineering tour above those two.

---

## 1. Feature inventory

The Portal delivers a **portfolio** of compliance-and-security services
to tenant customers. CVE Intelligence is the wedge product that
shipped first; the same multi-tenant primitives carry the rest of the
roadmap.

Status keys: ✅ shipped on branch · 🟡 partial · ⏳ planned

### 1.1 Tenant & access management — the platform layer

| Feature | Status | One-line value |
|---|---|---|
| Multi-tenant onboarding (CRUD + status lifecycle) | ✅ | One Portal instance serves many customers — operational leverage + recurring revenue |
| Per-tenant token issuance (bcrypt-hashed secrets, scopes, rotation) | ✅ | Zero-downtime token rotation — required for SOC 2 / ISO 27001 customers |
| Token usage tracking (last_used_at, IP) | ✅ | Detect unused or unexpected tokens; one-click revoke |
| Tier model (Free / Standard / Premium / Air-gapped) | 🟡 | Field exists; enforcement planned |
| Operator admin console (React) | ✅ | Day-1 productivity for operators — no curl/jq |
| Customer "My Products" UI (React) | ✅ | Visible product — CISO can see what they're paying for |

### 1.2 CVE Intelligence — the first product

| Feature | Status | One-line value |
|---|---|---|
| CVE feed aggregation (NVD + CISA KEV) | ✅ | Portal owns the heavy data layer — customers don't pull 100K+ CVEs |
| Bucket + vendor classification (operator-curated taxonomy) | ✅ | Customers care about *their* products — this is the noise-cutting move |
| Per-tenant inventory catalog (CPE-style) | ✅ | Input to the matching engine — without it, only coarse filtering |
| Tenant enrollments + vendor subscriptions | ✅ | Customer's preference state lives in the Portal; AAC reinstalls don't lose it |
| Filter preferences (severity threshold, KEV passthrough, tag-only, auto-apply) | ✅ | Dials that turn a firehose into a feed a security team trusts |
| CVE matching engine (per-tenant, idempotent) | ✅ | Operator-side compute — customers don't grind through full catalog nightly |
| Per-tenant authenticated feed API (incremental, cursor-paginated) | ✅ | Stable contract that AAC's EDA polls; customers can build their own integrations |
| Ack / suppress workflow with audit trail | ✅ | Auditor asks *"why didn't you patch CVE-X?"* — customer has a written record |
| Vendor remediation guidance (RHSA / USN / KB links) | ✅ | Closes the loop from *"problem"* to *"fix"* — feeds AAC remediation playbooks |
| AAC bridge integration (EDA rulebook + remediation workflow library) | 🟡 | The plumbing between Portal and customer environment |
| RHSA / USN / KB direct feed adapters (auto-populate vendor remediations) | ⏳ | Today's vendor remediations are seeded manually for the demo |
| Vendor PSIRT direct adapters (Cisco, Palo Alto, Fortinet, MSRC, Juniper) | ⏳ | Reduces lag between vendor advisory and matched delivery |
| SBOM ingestion (CycloneDX / SPDX) | ⏳ | Image-level inventory beyond OS packages |
| Auto-classifier ML upgrade (current is heuristic) | ⏳ | Reduce operator-side tagging effort |

### 1.3 Compliance-as-a-service core — the next strategic block

| Feature | Status | One-line value |
|---|---|---|
| Policy injection — operator-pushed Rego bundles | ⏳ | Operator ships a new framework (CIS M365 v4.1, custom corporate policy) once; every subscribed tenant gets it on next poll |
| **Customer-specific policy repo ingestion (consume from customer git)** | ⏳ | Inverted from operator-push: customer brings/manages their own policy repo; Portal syncs it. The two paths coexist — operator content for shared frameworks, customer content for org-specific rules |
| Compliance-framework enrollment (CIS RHEL/Windows, CIS M365, NIST 800-53, ISO 27001, SOC 2, PCI-DSS, NERC-CIP, …) | ⏳ | Same enrollment-and-subscription model as CVE buckets, applied to frameworks. Tenant subscribes, AAC instance evaluates, Portal aggregates posture |
| **Inventory-driven automatic enrollment** | ⏳ | Suggest frameworks based on what the customer runs ("you have M365 → CIS M365 Foundations"); customer confirms before enrollment fires. Rules engine over `tenant_inventory_catalog` |
| **"Backup → Patch → Validate" normalized workflow contract** | ⏳ | Every remediation workflow follows the same three-step shape; vendor-specific Ansible roles slot into Patch. Spec + reference roles for RHEL / Windows / Cisco / VMware |
| Multi-framework dashboards (per-tenant) | ⏳ | One screen across all enrolled frameworks; trends over time; drill-down |
| Cross-tenant operator dashboards | ⏳ | Operator-side benchmarking and account-health view |
| Audit evidence collection + delivery | ⏳ | Tenant requests evidence for framework + time range → Portal generates bundle (PDF + JSONB) for the auditor |
| **Audit certification — signed authoritative bundles** | ⏳ | Distinct from evidence delivery: Portal signs the bundle as authoritative, attaches chain-of-custody (Rego SHA, OPA bundle version, inventory snapshot), output directly ingestible by 3PAO / auditor without further transformation |
| **Baselining outputs (per-tenant baseline snapshots + diff)** | ⏳ | Point-in-time snapshot of (inventory × compliance × CVE matches); diff between two baselines answers "what changed since last audit?" |
| **Technical-debt heat map UI** | ⏳ | Surfaces existing AAC `technical_debt` schema (per-domain rates, OT/IT budget separation) as a $-denominated remediation backlog visualized per BU / framework / vendor |
| Historical compliance API (read over `compliance_results`) | ✅ | Existing endpoint set from pre-CVE work; React surface pending |

### 1.4 Operational guarantees — SLAs, status, billing

| Feature | Status | One-line value |
|---|---|---|
| Tier enforcement (rate limits, feature gates) | ⏳ | Today the tier is metadata; planned: real gates on feed cadence, history depth, auto-apply, framework count |
| Documented SLAs per tier (uptime, feed freshness, support response, time-to-policy-update) | ⏳ | Required for any enterprise sale beyond the wedge |
| Public status page (component health, last-data-freshness per source) | ⏳ | Trust signal; reduces inbound support load on incidents |
| Operator metrics + observability (Prometheus) | ⏳ | Internal: feed run duration, per-tenant request rate, last-seen per token |
| Backup + DR playbook (multi-tenant selective restore) | ⏳ | Required for production; not exercised in POC |
| Billing surface (usage metering + invoicing) | ⏳ | Commercial wiring; depends on D1 pricing decision below |
| Air-gap bundle pipeline (signed offline feed) | ⏳ | Defense / sovereign customers — strategic margin |
| Multi-region deployment (GDPR data residency) | ⏳ | Required for some EU customers |

### 1.5 SaaS / Cloud Services SLA monitoring — new dimension

| Feature | Status | One-line value |
|---|---|---|
| **SaaS / Cloud SLA monitoring** | ⏳ | Monitor whether the customer's contracted SaaS / cloud providers (AWS, Azure, M365, GitHub, etc.) are meeting *their* SLAs. Data: vendor health APIs + customer-supplied probes. Output: SLA breach events, dashboard, audit-evidence inclusion |
| Vendor SLA contract registry | ⏳ | Per-tenant store of "what SLA did the customer sign with each vendor" so the monitor knows the threshold to evaluate against |
| SLA-breach correlation with compliance findings | ⏳ | Connect SLA breaches to the compliance controls they impact (e.g. an availability-SLA breach is evidence for the auditor that the BCP control failed) |

### 1.6 Threat-intel adjacencies — roadmap

| Feature | Status | One-line value |
|---|---|---|
| IoC / threat-intel sharing (STIX/TAXII in, signed bundles out) | ⏳ | Same plumbing as CVE feed; same matching engine against tenant inventory |
| Vendor / supply-chain advisories (beyond CVE — EOL announcements, dep updates) | ⏳ | The "what should I be patching even if there's no CVE yet" question |

---

## 2. The one-paragraph summary

The AAC Customer Portal is a **multi-tenant compliance-as-a-service
hub** sitting above the AAC platform. AAC runs in each customer's
environment as a read-only compliance engine. The Portal aggregates
public CVE feeds, hosts and rotates policy bundles, lets each tenant
declare which compliance frameworks and CVE categories they care
about, matches both against the tenant's pushed inventory, and
delivers a personalized stream of CVE findings + policy updates +
audit evidence back to the tenant's environment. CVE Intelligence
shipped first as the wedge; the rest of the portfolio (policy
injection, compliance enrollment, multi-framework dashboards, audit
evidence delivery) is what makes this a service rather than a
feature.

---

## 3. Strategic focus

### 3.1 The market opening

Two complementary pains:

1. **VM-tool replacement.** Mid-market customers pay $150K–$500K+/yr
   for Nessus / Tenable / Qualys / Rapid7 — for a feed plus a matching
   engine. Those tools stop at the assessment line; remediation goes
   to a ticket queue or a second tool. AAC already does the harder
   half (execution via Ansible). The Portal closes the loop with a
   focused CVE feed wired straight into AAP job templates.
2. **Compliance-as-a-service.** Compliance budgets are 10–20× larger
   than IT-automation budgets, and partial coverage is a non-starter
   for regulators. Customers running multiple frameworks (SOC 2 + PCI
   + HIPAA, or NERC-CIP + NIST 800-82) currently herd spreadsheets
   and screenshot evidence. The Portal centralizes framework
   enrollment, policy distribution, posture rollup, and audit
   evidence — turning AAC from a tool-you-run into a service-you-buy.

CVE Intelligence is the **wedge**: small surface, clear value, fast
TTV. Compliance-as-a-service is the **expansion**: bigger ACV, longer
contracts, stickier customers. Both ride the same multi-tenant
primitives.

### 3.2 Where the Portal sits in the AAC story

| Layer | What it does | Where it runs |
|---|---|---|
| **AAC core** | Read-only compliance engine — fact collection, OPA evaluation, PostgreSQL history | In the customer's environment |
| **Portal** | Multi-tenant SaaS hub — CVE intelligence, policy distribution, framework enrollment, posture rollup, audit evidence, billing | Operator-hosted (or self-hosted for air-gap) |
| **AAC bridge (`aac-portal-bridge` role)** | Authenticated tunnel between on-prem AAC and the Portal — inventory push, CVE feed pull, policy bundle pull, evidence push | Inside the customer's AAC stack |

Architectural principle: **the customer's compliance data stays in
their environment.** The Portal sees inventory metadata, generated
matches, and evidence the customer chooses to deliver — never raw
compliance facts, mailbox contents, or configuration secrets. That's
what makes the Portal viable for regulated and sovereign customers.

---

## 4. The end goal

By the end of the work currently in flight (Pieces 1–11 on the
`feat/cve-intelligence` branches), the Portal supports the CVE
Intelligence loop end-to-end. The next strategic block (policy
injection + framework enrollment + audit evidence) is what turns the
Portal into the compliance-as-a-service product, and is what this
brief surfaces alongside the CVE work.

A "complete" Portal day-in-the-life:

1. Operator stands up the Portal (FastAPI + Postgres + React).
2. Customer's AAC bridge pushes inventory and pulls policy bundles on
   schedule.
3. Customer subscribes to (a) the CVE buckets they run and (b) the
   compliance frameworks they're audited against. Customer sets
   preferences (severity threshold, KEV pass-through, auto-apply,
   evidence delivery cadence).
4. Portal aggregates external feeds, classifies, matches, distributes.
5. Customer's AAC EDA polls the Portal; remediation workflows fire
   automatically for KEV (if opted in), advisory-only otherwise.
6. Compliance results from each enrolled framework flow back into the
   Portal as posture data and rolled-up audit evidence.
7. CISO sees one dashboard: CVE posture, compliance posture per
   framework, audit-readiness, trend lines. Auditor receives a signed
   evidence bundle on request.

---

## 5. Architecture at a glance

```
                          OPERATOR-HOSTED
                          ┌──────────────────────────────────────────┐
                          │ AAC Customer Portal                       │
                          │                                           │
   NVD ─── ingest ──────▶ │ ┌──────────────┐  ┌────────────────────┐ │
   CISA KEV ──ingest ───▶ │ │ FastAPI      │  │ PostgreSQL          │ │
   RHSA/USN/KB (⏳) ────▶ │ │ /api/admin/  │  │ tenants             │ │
   PSIRT feeds (⏳) ────▶ │ │   /api/portal│  │ tenant_tokens       │ │
   STIX/TAXII (⏳) ─────▶ │ │              │  │ cve_events          │ │
                          │ │              │  │ cve_bucket_tags     │ │
   policy bundles ◀─────  │ │              │  │ cve_vendor_tags     │ │
   (cis_m365,             │ │              │  │ tenant_enrollments  │ │
    cis_rhel9, …)         │ │              │  │ tenant_inventory_   │ │
                          │ │              │  │   catalog           │ │
   evidence ─────────▶    │ │              │  │ tenant_cve_matches  │ │
   (PDF + JSONB)          │ │              │  │ framework_enroll-   │ │
                          │ │              │  │   ments (⏳)        │ │
                          │ │              │  │ policy_bundles (⏳) │ │
                          │ └──────┬───────┘  │ posture_rollup (⏳) │ │
                          │        │          └────────────────────┘ │
                          │ ┌──────▼───────┐                          │
                          │ │ React (Vite) │                          │
                          │ │ Operator     │                          │
                          │ │ My Products  │                          │
                          │ └──────────────┘                          │
                          └─────────────┬────────────────────────────┘
                                        │
                                        │ HTTPS — per-tenant bearer
                                        │
                          ┌─────────────▼────────────────────────────┐
                          │ CUSTOMER ENVIRONMENT — AAC stack          │
                          │                                           │
                          │ ┌──────────────────────────────────────┐  │
                          │ │ aac-portal-bridge role               │  │
                          │ │  • inventory push (nightly)           │  │
                          │ │  • CVE feed pull (EDA polling)        │  │
                          │ │  • policy bundle pull (⏳)            │  │
                          │ │  • evidence push (⏳)                 │  │
                          │ │  • remediation workflow trigger       │  │
                          │ └────────┬─────────────────────────────┘  │
                          │ ┌────────▼────────┐  ┌──────────────────┐ │
                          │ │ AAP 2.6 + EDA   │  │ OPA × 3 + Postgres│ │
                          │ │ + job templates │  │ (AAC standard)    │ │
                          │ └─────────────────┘  └──────────────────┘ │
                          └───────────────────────────────────────────┘
```

Two surfaces, two trust boundaries. The Portal never reaches into the
customer's environment — the bridge pushes and pulls.

For the full schema, table-by-table breakdown, and API contract see
`docs/cve_intelligence_architecture.md`.

---

## 6. Feature deep-dive — value, status, code pointers

For each feature: what it does, whose pain it removes, current status,
code reference. Grouped to match § 1.

### 6.1 Tenant & access management

#### Multi-tenant management
One Portal instance, many customers. Each tenant has display name,
contact email, tier, AAC-bridge URL, status, notes. CRUD via
`/api/admin/v1/tenants`. **Value:** multi-tenancy is the difference
between a tool and a service. **Code:** `api/src/routers/tenants.py`,
frontend `TenantsPage.tsx` + `TenantDetailPage.tsx`. ✅

#### Token issuance + rotation
Bearer tokens with `token_id` (public) + `token_secret` (bcrypt-hashed,
shown once). Scopes per token; revocable individually. Multiple active
tokens per tenant for zero-downtime rotation. **Value:** mandatory for
customers under SOC 2 / ISO 27001 secret-rotation policy. **Code:**
`api/src/routers/tenants.py`, `api/src/core/tenant_auth.py`. ✅

#### Operator admin console + My Products UI
Browser app for operators (Dashboard, Tenants, Feeds, CVEs, Taxonomy)
and customers (My Products — feed browser with ack/suppress).
**Value:** day-1 productivity; visible product for sales demos.
**Code:** `frontend/src/pages/`. ✅

### 6.2 CVE Intelligence

#### CVE feed aggregation
NVD (full catalog, paginated) + CISA KEV (Known Exploited
Vulnerabilities) ingest, scheduled. Each run records `feed_runs` row
with counts and errors. **Value:** one place to add a new feed; every
tenant inherits. **Code:** `api/src/feeds/nvd.py`,
`api/src/feeds/cisa_kev.py`. ✅

#### Bucket + vendor classification
Operator-curated two-axis taxonomy. Buckets are semantic categories
(`rhel`, `windows`, `ot_scada`, `microsoft365`); vendors are
publishers (`redhat`, `microsoft`, `cisco`). CVEs get tagged auto +
operator. **Value:** the noise-cutting move — customers only see
matches against their categories. **Code:**
`api/src/routers/classification.py`, seed taxonomy in
`migrations/003a_taxonomy_seed.sql`. ✅

#### Per-tenant inventory catalog
Tenant pushes installed-software inventory (CPE-style triples) on a
schedule. Aging timestamps drop products that disappear. **Value:**
the input to matching — without it, only coarse filtering. **Code:**
schema in `migrations/001_cve_intelligence.sql`; ingest endpoint in
the `compliance#210` AAC-side branch. ✅ Portal / 🟡 AAC

#### Enrollments + vendor subscriptions + filter preferences
Per-tenant declarations: bucket enrollments (coarse opt-in), vendor
subscriptions (allow/block per vendor), preferences (severity
threshold, KEV pass-through, tag-only delivery, auto-apply-KEV).
**Value:** the dials that turn a firehose into a feed a security
team trusts. **Code:** `api/src/routers/enrollments.py`. ✅

#### CVE matching engine
Per-tenant compute: joins inventory × CVEs × tags × enrollments ×
preferences. Idempotent. Stamps `matched_at` and writes the matching
reason (bucket key, vendor key, or "kev"). **Value:** operator-side
compute saves the customer's AAC from grinding through the catalog
nightly. **Code:** `api/src/feeds/matcher.py`. ✅

#### Per-tenant feed API + ack/suppress
`/api/portal/v1/tenants/{id}/cves` with bearer auth, `since=`,
`cursor=`. Stamps `delivered_at` on read. POST `/ack` and
`/suppress` (with reason). **Value:** stable contract AAC's EDA polls;
audit trail for suppressions. **Code:** `api/src/routers/portal_feed.py`. ✅

#### Vendor remediation guidance
Each CVE has a parallel `cve_vendor_remediations` table linking to
vendor advisories (RHSA, USN, KB) with `fixed_version` +
`advisory_url`. Delivered only for vendors the tenant subscribes to.
**Value:** closes the loop from "problem" to "fix"; AAC remediation
workflows consume this directly. **Code:** schema in
`migrations/005_cve_feed_api.sql`; delivery in `portal_feed.py`. ✅
Seed pipeline from RHSA/USN ⏳.

### 6.3 Compliance-as-a-service core — the planned block

#### Policy injection
Operator publishes Rego policy bundles (a new CIS framework, a
revision to an existing one, a customer-specific custom policy). The
Portal hosts the bundle with semver + sha256 signature. Customers'
AAC bridges poll the Portal for updated bundles; on a new version,
the bridge fetches, verifies the signature, swaps in OPA via bundle
mode (see § 6.4 below). **Value:** the operator ships compliance
content **once**; every subscribed tenant gets it on next poll
without a release engineering effort on the customer side. **Status:**
⏳ design only. **Depends on:** OPA bundle mode (already tracked as
task #45 in the AAC product backlog).

#### Compliance-framework enrollment
Same shape as CVE bucket enrollment, applied to frameworks. Tenant
subscribes to CIS RHEL 9 + CIS M365 + NIST 800-53 + ISO 27001 + SOC 2
(whichever apply). The Portal's policy-injection layer pushes the
right bundle to that tenant; the customer's AAC schedules
assessments; results flow back to the Portal as posture data. **Value:**
the customer enrolls once; framework-level posture management,
distribution, and rollup is centralized. **Status:** ⏳ design only.

#### Multi-framework dashboards
Per-tenant rollup of every enrolled framework's compliance %, trend
over time, top failing controls, evidence index. Cross-framework
control-overlap detection ("CIS 1.1.1 + NIST AC-2 + ISO A.9 all
covered by this one finding"). **Value:** auditors and CISOs see one
screen instead of N. **Status:** ⏳ data shape exists in
`compliance_results`; the Portal-side dashboards are not built.

#### Audit evidence collection + delivery
Tenant requests an evidence package — framework, time range,
optionally specific controls. Portal generates a signed bundle (PDF
report + raw evidence JSONB from `compliance_results` + chain of
custody) for delivery to the auditor. **Value:** turns audit prep
from a weeks-long scramble into a one-click export. **Status:** ⏳
schema not yet defined.

### 6.4 Operational guarantees

#### Tier enforcement
Today the `tenants.tier` field is metadata. Planned: rate-limiter
middleware keyed on `tenant_id` + tier; feature gates on feed
cadence, history depth, framework count, auto-apply, evidence export
volume. **Value:** required for any commercial offering with
differentiated pricing. **Status:** ⏳.

#### SLAs per tier
Documented commitments per tier:

| Dimension | Free | Standard | Premium | Air-gapped |
|---|---|---|---|---|
| Portal API uptime | best-effort | 99.5 % | 99.9 % | self-hosted (customer-owned) |
| CVE feed freshness | daily | hourly | real-time push | bundle delivery (operator publishes daily, customer pulls on schedule) |
| Policy bundle freshness | weekly | daily | on-publish | bundle delivery |
| Support response | community | 1 business day | 4 hours (P1) | dedicated channel |
| Time-to-policy-update (new CIS release) | next monthly cycle | 7 days | 48 hours | bundle delivery |
| Evidence export | self-serve, monthly cap | self-serve | priority + signed | priority + signed + offline |

**Status:** ⏳ targets above are illustrative; actual SLAs are
commercial / leadership decisions.

#### Status page, observability, billing, DR
See §1.4 for the planned items in this block.

### 6.5 Threat-intel adjacencies — roadmap

Same multi-tenant primitives apply. STIX/TAXII feeds → operator
review → tenant subscription → matching against inventory → delivery
through the bridge. EOL announcements and supply-chain advisories
(beyond CVE) ride the same pipeline.

---

## 7. How the Portal integrates with AAC — end-to-end

Walk an event through the full system. (Sub-steps below show the
broader scope, not just CVE.)

### 7.1 Inventory flow (customer → Portal, daily)

AAC bridge reads `compliance_results` via the read-only
`compliance_reader` Postgres role, groups packages into CPE-style
triples, POSTs to `/api/admin/v1/tenants/{id}/inventory/upsert` over
authenticated HTTPS. Portal updates `tenant_inventory_catalog`, ages
out stale entries. **Status:** ✅ Portal side / 🟡 AAC side.

### 7.2 Policy bundle flow (Portal → customer, on bundle publish) — ⏳

Operator publishes a Rego bundle to the Portal — e.g. `cis_m365_v4.0.0`
or a custom corporate policy. Portal computes sha256 + signs.
Customer's AAC bridge polls the Portal's `/api/portal/v1/tenants/{id}
/policy-bundles` endpoint; on a new version, downloads + verifies the
signature + reloads OPA in bundle mode. **Depends on:** task #45 (OPA
bundle mode) + tenant subscription to the relevant framework.

### 7.3 CVE feed flow (sources → Portal, hourly)

Scheduled ingest hits NVD + CISA KEV (today) — RHSA/USN/KB/PSIRT
adapters land in roadmap. Each CVE upserts to `cve_events`;
auto-classifier tags candidate buckets/vendors; operator confirms
through the CVE browser UI.

### 7.4 Match flow (Portal, per-tenant)

`feeds/matcher.py` joins inventory × CVEs × tags × enrollments ×
preferences → `tenant_cve_matches` rows with `delivered_at = NULL`.

### 7.5 Delivery flow (Portal → customer, EDA polling)

EDA rulebook `aac_portal_feed.yml` polls `/api/portal/v1/tenants/{id}
/cves?since=<last>`. Portal stamps `delivered_at`. EDA fires events;
AAP routes KEV+auto-apply → remediation workflow, else → notification
workflow.

### 7.6 Compliance evaluation flow (customer-internal, scheduled)

Customer's AAC runs assessments against enrolled frameworks. Results
land in customer's `compliance_results`. The bridge ships rolled-up
posture (% per framework, last-run timestamp) to the Portal —
not the raw facts. **Status:** ⏳ rollup endpoint not yet defined.

### 7.7 Audit evidence flow (customer → Portal → auditor, on demand) — ⏳

Customer requests evidence in the UI ("PCI-DSS evidence for Q2 2026").
Bridge collects the relevant `compliance_results` rows, plus any
linked artifacts (Ansible facts, OPA decision logs), signs them,
pushes to the Portal's evidence-store. Portal generates the
auditor-facing PDF + raw bundle and delivers it via a one-time-use
signed URL.

### 7.8 Acknowledgment / suppression flow (customer → Portal)

User action in My Products or AAC remediation auto-ack on successful
patch. POST `/ack` or `/suppress`. Future polls don't re-deliver. ✅

The whole loop is **idempotent** end-to-end. Critical for a system
where networks drop polls, customers retry inventory pushes, or
remediation replays.

---

## 8. Multi-tenant model + auth

The platform's two-key insight is **isolation by path + auth scheme**.

| Auth scheme | Bearer | Used for | Endpoints |
|---|---|---|---|
| Operator admin | `PORTAL_ADMIN_TOKEN` (single, env-injected) | Operator CRUD, taxonomy curation, classifier runs, feed triggers, per-tenant enrollment/preference editing | `/api/admin/v1/*` |
| Per-tenant | `token_secret` (bcrypt-verified) + `X-Token-Id` header | Tenant pulls their own CVE feed, ack/suppress, evidence requests, policy bundle downloads | `/api/portal/v1/tenants/{tenant_id}/*` |
| (Planned) Customer SSO | OIDC via customer IdP | My Products UI for customer end-users | `/my-products/*` |

The `tenant_id` is in every customer-facing URL path. Combined with
the per-tenant token check in `core/tenant_auth.py`, it's **provably
impossible** for one tenant to read another tenant's matches —
something Nessus's multi-tenant model never claimed.

Core tables that anchor multi-tenancy:

- `tenants` — tenant identity, tier, status, AAC-bridge URL
- `tenant_tokens` — bcrypt-hashed secrets, scopes, last-used tracking
- `tenant_inventory_catalog` — what each tenant runs
- `tenant_enrollments` — buckets the tenant subscribes to
- `vendor_subscriptions` — per-vendor allow/block
- `filter_preferences` — severity / KEV / auto-apply settings
- `tenant_cve_matches` — the output of the matching engine
- `framework_enrollments` (⏳) — frameworks the tenant subscribes to
- `policy_bundle_subscriptions` (⏳) — which bundles each tenant pulls
- `posture_rollup` (⏳) — per-framework compliance % over time
- `evidence_requests` (⏳) — audit evidence package requests

---

## 9. Customer options — what we sell

### 9.1 Tier matrix

The tier field is in the `tenants` table today; *enforcement* of tier
limits is planned (§ 1.4). Illustrative values below — actual numbers
are commercial decisions.

| Capability | Free | Standard | Premium | Air-gapped |
|---|---|---|---|---|
| Target customer | Small shops / evaluation | Mid-market enterprise | Large enterprise + regulated | Defense, utilities, sovereignty |
| Tenancy | Single | Multi sub-tenant | Multi sub-tenant + sub-org | Self-hosted Portal |
| CVE feed cadence | Daily | Hourly | Real-time push | Bundle delivery |
| Inventory cadence | Manual | Daily | Continuous | Bundle delivery |
| Auto-remediation | Off | Optional, KEV only | Full (with policy) | Yes |
| Compliance framework enrollment | 1 framework | 5 frameworks | Unlimited | Unlimited |
| Policy injection (operator-pushed bundles) | No | Yes (daily poll) | Yes (on-publish webhook) | Bundle delivery |
| Audit evidence export | Self-serve, monthly cap | Self-serve | Priority + signed | Priority + signed + offline |
| Multi-framework dashboards | — | Yes | Yes | Yes |
| Cross-tenant rollup (for operators within the customer) | — | — | Yes | Yes |
| Vendor PSIRT direct feeds | — | — | Yes | Yes |
| Air-gap support | No | No | No | Yes |
| Portal API uptime SLA | best-effort | 99.5 % | 99.9 % | self-hosted (customer-owned) |
| Support response | Community | 1 business day | 4 hours P1 | Dedicated channel |
| Time-to-policy-update (new CIS) | Next monthly cycle | 7 days | 48 hours | Bundle delivery |

### 9.2 Deployment models

1. **Operator-hosted Portal in our cloud.** Customer's AAC talks to
   our Portal URL. Lowest friction, fastest TTV. Most commercial
   customers land here.
2. **Operator-hosted Portal in customer cloud (their AWS/Azure/GCP
   account).** Same code, customer-owned data plane. Required for
   some financial / federal customers.
3. **Customer-hosted Portal (self-managed).** Same code, customer
   runs and patches it themselves. Required for air-gapped / SCIF /
   classified networks.

### 9.3 Integration paths

| Path | What they get | What they bring |
|---|---|---|
| CVE Intelligence only | CVE feed + matching + remediation workflows | Existing AAP + the `aac-portal-bridge` role |
| Compliance-as-a-service only | Framework enrollment + policy distribution + posture rollup + audit evidence (⏳) | Existing AAC |
| Full AAC + Portal | Everything — multi-framework compliance + CVE + audit-grade evidence | A bare RHEL host (or use the greenfield install) |

The "Full AAC + Portal" path is the **strategic target**: highest
ACV, highest customer value, deepest moat.

---

## 10. Customer focus — primary use cases

### 10.1 *"Replace our Nessus subscription"*

**Profile:** 500–5 000-host mid-market enterprise. Pays $200K–$400K/yr
for Nessus / Tenable. Has Ansible for everything else.

**What they want:** the vulnerability data + cheaper + with
remediation built in.

**What we offer:** Portal Standard tier + full AAC bundle.

**Where it bites:** Nessus authenticated scans poke deep into hosts;
AAC's fact-based approach is shallower. Customers with explicit
"authenticated scanner" policy need a compensating control.

### 10.2 *"Compliance reporting our auditors believe"*

**Profile:** Regulated organization (financial, healthcare, utility).
Multiple frameworks. Audit prep is a quarterly fire drill.

**What they want:** continuous evidence collection across all
frameworks; cross-framework rollup; 12-month history; one-click
auditor delivery.

**What we offer:** Portal Premium + AAC + the planned audit-evidence
delivery path (§ 7.7). CVE feed bundles in for free.

**Where it bites:** Some audit programs require specific tools
(FedRAMP 3PAO). Position AAC as the *evidence layer*, complementary.

### 10.3 *"Air-gapped sovereignty"*

**Profile:** Defense, utilities, classified, banking-air-gap. AAP
already approved.

**What they want:** compliance + CVE + policy distribution without
phoning home. Audit-trail integrity (proof of authoritative policy
provenance).

**What we offer:** Portal Air-gapped tier — operator publishes
signed bundles out-of-band. Customer's self-hosted Portal ingests.

**Where it bites:** Operationally heavier on us; we sign, publish,
ship bundles. Multi-year sticky contracts; strategic margin.

### 10.4 *"Centralized policy for distributed business units"* (new)

**Profile:** Large enterprise with 5–20 business units, each
running its own AAC + AAP locally. Centralized GRC team wants
**one policy of record** but doesn't want to run the assessments.

**What they want:** publish the corporate compliance policy once;
have every BU's AAC pick it up automatically; roll posture up to
HQ; auditor-grade evidence per BU and aggregated.

**What we offer:** Portal Premium + policy injection (§ 6.3) + the
multi-framework dashboards (§ 6.3 cross-tenant view). Each BU is a
sub-tenant. HQ gets the operator dashboard for their own org.

**Where it bites:** Org structure complexity — multi-level tenancy
(parent + sub-tenants with separate AAC bridges) isn't shipped yet.
A pre-sales conversation about hierarchy is mandatory.

---

## 11. What's done vs what's in flight

### 11.1 CVE Intelligence work — Pieces 1–11

| # | Piece | Status |
|---|---|---|
| 1 | AAC schema migration playbook | ✅ shipped |
| 2 | AAC inventory collector playbook | ✅ shipped |
| 3 | AAC inventory API endpoint | ✅ shipped |
| 4 | Portal: tenant + token onboarding | ✅ shipped |
| 5 | Portal: CVE feed adapters (NVD + CISA KEV) | ✅ shipped |
| 6 | Portal: bucket + vendor classification | ✅ shipped |
| 7 | Portal: matching engine | ✅ shipped |
| 8 | Portal: per-tenant CVE feed API | ✅ shipped |
| 9 | AAC: `aac_portal_feed` EDA rulebook | ✅ shipped |
| 10 | AAC: CVE remediation workflow library | ✅ shipped |
| 11 | Portal: My Products + Operator UI | ✅ shipped |

### 11.2 Compliance-as-a-service — next block (⏳)

| # | Piece | Status | Email function |
|---|---|---|---|
| 12 | RHSA / USN / KB feed adapters (vendor remediations) | ⏳ planned | #2 (CVE remediation enablement) |
| 13 | Policy bundle hosting + signature scheme (operator-pushed) | ⏳ planned (depends on AAC task #45) | #1 |
| 14 | Customer-side policy bundle pull (bridge) | ⏳ planned | #1 |
| 15 | Framework enrollment schema + API | ⏳ planned | #3 |
| 16 | Posture rollup ingest + API | ⏳ planned | #5 |
| 17 | Multi-framework dashboard (React) | ⏳ planned | #5 |
| 18 | Cross-tenant operator dashboard (React) | ⏳ planned | #5 |
| 19 | Audit evidence schema + signed bundle generator | ⏳ planned | #5 |
| **20** | **Customer-specific policy repo ingestion** (consume from customer's git, distinct from operator-pushed bundles in #13) | ⏳ planned | **#1** |
| **21** | **"Backup → Patch → Validate" normalized workflow contract** + reference per-vendor roles | ⏳ planned | **#2** |
| **22** | **SaaS / Cloud Services SLA monitoring** (AWS Health, Azure Service Health, M365 Service Status + custom probes) | ⏳ planned | **#4** |
| **23** | **Inventory-driven automatic enrollment** (suggest frameworks based on what the customer runs) | ⏳ planned | **#3** |
| **24** | **Baselining outputs** (per-tenant point-in-time snapshots + baseline diff) | ⏳ planned | **#6** |
| **25** | **Technical-debt heat map UI** (surfaces existing AAC technical_debt schema in the Portal) | ⏳ planned | **#6** |
| **26** | **Audit certification** — signed authoritative bundles with chain-of-custody (distinct from #19 evidence delivery) | ⏳ planned | **#5** |

### 11.3 Operational + commercial — required for GA

| # | Piece | Status |
|---|---|---|
| 27 | Tier enforcement middleware | ⏳ planned |
| 28 | Documented SLAs per tier (the Portal's own SLAs to tenants — distinct from #22) | ⏳ commercial decision |
| 29 | Public status page | ⏳ planned |
| 30 | Operator observability (Prometheus) | ⏳ planned |
| 31 | Backup + DR playbook (multi-tenant selective restore) | ⏳ planned |
| 32 | Billing surface | ⏳ depends on pricing model |
| 33 | Air-gap bundle pipeline | ⏳ planned |
| 34 | Multi-region deployment (GDPR) | ⏳ planned |
| 35 | Auto-classifier ML upgrade | ⏳ planned |
| 36 | Vendor PSIRT direct adapters | ⏳ planned |
| 37 | SBOM ingestion (CycloneDX / SPDX) | ⏳ planned |
| 38 | IoC / threat-intel sharing | ⏳ planned |

### 11.4 Open PRs at time of writing (2026-06-02)

| Repo | PR | Status |
|---|---|---|
| `compliance` | #210 | CVE Intelligence AAC side (Pieces 1, 2, 3, 9, 10) |
| `AAC_Customer_Portal` | #2 | CVE Intelligence Portal side (Pieces 4–8) + frontend (Piece 11) |
| `compliance` | #211 | Customer integrations scaffolding folder |
| `compliance` | #212 | CIS M365 Foundations assessment (AAP side) |
| `rego_policy_libraries` | #24 | CIS M365 Rego bundle |
| `compliance` | #213 | M365 POC Statement of Work |

---

## 12. Known gaps + decisions still pending

### Technical

| # | Gap | Recommended next step |
|---|---|---|
| G1 | No tier enforcement | Rate-limiter middleware keyed on tenant_id; feature gates by tier |
| G2 | No metrics / observability for the Portal itself | Prometheus instrumentation: feed run duration, match count per tenant, API request rate per tenant, last-seen per token |
| G3 | No SBOM ingestion — inventory is package-level | Accept CycloneDX / SPDX; extend `tenant_inventory_catalog` to image-level |
| G4 | No vendor PSIRT direct adapters | Cisco PSIRT, MSRC, Red Hat Security Data API as the next three |
| G5 | Auto-classifier is heuristic | LLM-assisted suggestion with operator review |
| G6 | Reset / DR untested | Backup + restore drill; multi-tenant selective restore |
| G7 | No multi-region deployment story | Required for some EU customers (GDPR) |
| G8 | Policy injection depends on OPA bundle mode | Bundle mode is AAC task #45 — Portal feature gates on that landing |
| G9 | Framework enrollment + posture rollup schema not yet designed | Design doc before sprint commitments |
| G10 | Audit evidence schema + signing not yet designed | Design doc — what gets signed, by which key, with what chain of custody |
| G11 | No hierarchical tenancy (parent → sub-tenants) | Required for use case § 10.4; design + schema work |

### Product / commercial

| # | Decision pending | Owner |
|---|---|---|
| D1 | Pricing model — per-host, per-tenant, per-framework, flat-fee, or hybrid? | Sales / leadership |
| D2 | Free tier limits (how generous?) | Sales |
| D3 | Air-gap bundle delivery contract (who signs, how is integrity verified?) | Security / Engineering |
| D4 | Branding — "AAC Portal" vs new brand vs co-brand? | Product / Marketing |
| D5 | Support model — included or paid? Severity tiers + SLA? | Customer Success |
| D6 | Audit evidence — is the signed bundle binding evidence, or framework-of-evidence-for-an-auditor? | Legal |
| D7 | Customer SSO integration — which IdPs do we underwrite (Okta, Azure AD, Auth0)? | Engineering + Sales |

---

## 13. References

### Code

- **Portal repo:** `ynotbhatc/AAC_Customer_Portal`
  - `api/src/routers/tenants.py` — tenant + token CRUD
  - `api/src/routers/feeds.py` — feed runs
  - `api/src/routers/classification.py` — buckets + vendors
  - `api/src/routers/enrollments.py` — per-tenant settings + matches
  - `api/src/routers/portal_feed.py` — per-tenant authenticated feed
  - `api/src/feeds/nvd.py`, `cisa_kev.py` — ingest adapters
  - `api/src/feeds/matcher.py` — matching engine
  - `api/src/core/tenant_auth.py` — bcrypt bearer auth
  - `api/migrations/001_*.sql` … `005_*.sql` — schema
  - `frontend/src/pages/` — React pages (operator + My Products)

- **AAC compliance repo:** `ynotbhatc/compliance`
  - `ansible/roles/aac_portal_bridge/` — bridge container
  - `extensions/eda/rulebooks/` — `aac_portal_feed.yml` (PR #210)
  - `ansible/playbooks/aac_cve_*` — remediation workflow library

### Documents

- `docs/architecture.md` (portal repo) — original architecture
- `docs/cve_intelligence_architecture.md` — CVE feature architecture
- This brief — capabilities + focus tour

### People (assumed roles, fill in actuals)

- Tech lead — Portal + AAC bridge engineering ownership
- Product owner — backlog, customer asks, roadmap calls
- Sales engineer — first customer engagements
- Customer success — onboarding, training, day-2 ops

---

**Authored with Claude (Anthropic).**
