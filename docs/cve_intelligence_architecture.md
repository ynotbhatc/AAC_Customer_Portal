# CVE Intelligence — Architecture

End-to-end architecture for the CVE / patch intelligence feature added to the AAC Customer Portal.

---

## What this is

A multi-tenant CVE intelligence system that:

- Aggregates vulnerability feeds from multiple sources (NVD, CISA KEV, Red Hat Insights, MSRC, OSV.dev, vendor PSIRTs)
- Classifies each CVE into operator-curated buckets + vendor tags
- Pulls each tenant's installed inventory catalog from their on-prem AAC instance (nightly)
- Matches CVEs against tenant inventory at the CPE level (operator-side compute)
- Delivers per-tenant filtered notifications, including vendor-derivative remediations (RHSA / USN / KB / upstream) matched to the customer's enrollments
- Stores patch artifacts (mostly references, sometimes binaries) in S3
- Tracks delivery, customer acknowledgment, and downstream remediation lifecycle

---

## Surfaces

Three components, each in its own repo:

| Surface | Repo | Stack | Purpose |
|---------|------|-------|---------|
| **Marketing** | (separate, not in scope) | Next.js / Vercel — `xcomplai-ai.vercel.app` | Brand, lead-gen. Untouched by this work. |
| **Customer Portal** | `ynotbhatc/AAC_Customer_Portal` | FastAPI + asyncpg + React + Vite + Tailwind | Multi-tenant authenticated app — CVE intelligence + existing compliance domain |
| **AAC core** | `ynotbhatc/compliance` | Ansible + OPA + PostgreSQL | Runs in each customer's environment. Inventory collector, EDA event source, remediation workflows. |

CVE Intelligence work spans the **Customer Portal** + **AAC core** repos. Marketing is out of scope.

---

## Data flow — bidirectional pull

```
┌─ Customer's AAC install (per-customer) ────────────────────────────┐
│                                                                      │
│   compliance_results table (existing)                               │
│   installed_inventory     ← collector (Ansible package_facts)       │
│   inventory_catalog (mv)  ← dedupe'd rollup for portal              │
│                                                                      │
│   AAC API endpoint                                                   │
│      GET /api/aac/v1/inventory_catalog ──┐                          │
│                                           │                          │
└───────────────────────────────────────────┼──────────────────────────┘
                                            │
                              (portal pulls nightly + on-demand)
                                            │
┌───────────────────────────────────────────┼──────────────────────────┐
│ Central Portal (operator, multi-tenant)   │                          │
│                                           ▼                          │
│   tenant_inventory_catalog ← cached copy of each tenant's catalog   │
│                                                                      │
│   Feed adapters (background workers, scheduled)                     │
│     NVD · CISA KEV · Insights · MSRC · OSV · USN · Cisco PSIRT      │
│       │                                                              │
│       ▼                                                              │
│   cve_events (normalized common schema)                             │
│   cve_bucket_tags + cve_vendor_tags (classification)                │
│       │                                                              │
│       ▼                                                              │
│   Matching engine (SQL join)                                         │
│     cve_events × tenant_inventory_catalog × tenant_filter_prefs     │
│       │                                                              │
│       ▼                                                              │
│   Per-tenant CVE feed                                                │
│     GET /api/portal/v1/tenants/<id>/cves?since=<ts> ───┐            │
│                                                         │            │
└─────────────────────────────────────────────────────────┼────────────┘
                                                          │
                              (each tenant's AAC EDA polls)
                                                          │
┌─ Customer's AAC install ─────────────────────────────────┼──────────┐
│                                                          ▼          │
│   EDA activation: lab.eda.aac_portal_feed                            │
│      polls portal every N seconds, emits CVE events                  │
│       │                                                              │
│       ▼                                                              │
│   Rulebook fires by severity:                                        │
│      KEV + critical  → AAC_CVE_AutoApplyTier workflow                │
│      high            → AAC_CVE_TriageAndApprove workflow             │
│      med / low       → AAC_CVE_QueueForReview workflow               │
│                                                                      │
│   Workflows:                                                         │
│     Open ticket → (approval gate) → Backup → Apply → Validate →     │
│     [Close OR Rollback]                                              │
│                                                                      │
│   Persisted in: cve_events_received, cve_vendor_remediations,       │
│   cve_patch_archive, cve_host_matches, cve_remediation_actions      │
└──────────────────────────────────────────────────────────────────────┘
```

Both directions are **pulls** — initiator fetches, no inbound webhooks required on the customer's network.

---

## Data sovereignty

| Data | Direction | What flows | Volume |
|------|-----------|-----------|--------|
| Inventory catalog | AAC → Portal | Deduplicated `(vendor, product, version, host_count)` tuples — **not** hostnames, IPs, or per-host facts | ~400 rows per tenant |
| CVE feed | Portal → AAC | CVE record + vendor remediations + artifact references, filtered to tenant's enrollment | 5–20/day per tenant after filtering |

**No hostnames, IPs, or business labels leave the customer environment.** Sensitive products (internal app names) can be excluded via the "My Products" UI on the AAC side.

Air-gapped customers: alternative pattern — portal sends all CVEs in enrolled buckets (no per-tenant filtering at portal); customer's AAC does the matching locally with their own inventory. Premium tier — covered separately.

---

## S3 layout for patch artifacts

Three buckets, prefix-keyed.

```
aac-patches-shared/                  ← single bucket, shared across all tenants
  patches/
    <cve-id>/
      <vendor-advisory-id>/
        <package-version>.<arch>.<ext>     ← binary (if redistributable)
        metadata.json                       ← vendor info, sha256, signature
        manifest.json                       ← what's in the archive
  thumbprints/
    operator-signing-key.pub                ← for verifying operator-signed patches

aac-tenants/                          ← single bucket, tenant prefixes
  <tenant-uuid>/
    delivery-log/<YYYY>/<MM>/<DD>/<cve-id>.json
    inventory-uploads/<YYYY>/<MM>/<DD>/catalog.json.gz
    manual-overrides/<artifact-overrides>.json

aac-feeds-snapshots/                  ← single bucket, operator-only
  nvd/<YYYY>/<MM>/<DD>/cve-feed.json.gz
  msrc/<YYYY>/<MM>/cumulative-bulletin.xml
```

**Three buckets, not bucket-per-customer-per-product.** Per-tenant isolation via prefix + IAM policy + signed URLs. Deduplication of patch binaries is automatic (one byte-equal RPM is stored once and served to many).

### When the portal actually caches binaries (most tiers don't)

| Tier | What the portal stores | Customer fetches from |
|------|-----------------------|----------------------|
| **Free / Standard** | Reference only — vendor URL + sha256 + advisory text | Vendor CDN directly, with their entitlements |
| **Premium** | Cached binary in `aac-patches-shared` (when legally redistributable) | Portal S3 via signed URL (low latency) |
| **Air-gapped** | Cached binary + signed delta-update manifests | Operator-delivered out-of-band (media drops, mirror sync) |

For Red Hat / Microsoft / Cisco vendor-restricted content, the operator **cannot** legally redistribute. The portal stores the URL + metadata; the customer's AAC fetches with their own entitled credentials. This applies to most enterprise patches.

The portal stores binaries mostly for **OSS upstream patches** (nginx, postgres, Apache, OpenJDK) and **customer-uploaded artifacts** (their own internal app patches).

---

## Schemas

### AAC side (`compliance` PG database)

Lives in the `compliance` PostgreSQL database alongside `compliance_results`. Added by `ansible/playbooks/cve_portal_init_schema.yml`.

| Table / view | Purpose |
|--------------|---------|
| `installed_inventory` | Per-host package facts (populated by collector) |
| `manual_product_declarations` | Products `package_facts` can't see — custom internal apps, firmware, container images |
| `aac_instance_config` | Single-row tenant identity + portal credentials |
| `cve_events_received` | Local cache of CVEs delivered by portal |
| `cve_vendor_remediations` | Per-vendor derivative remediation (RHSA / USN / KB / upstream) |
| `cve_patch_archive` | Per-CVE artifact: pointer (default) or cached binary path |
| `cve_host_matches` | Which local hosts each CVE affects |
| `cve_remediation_actions` | Per-step lifecycle audit (snapshot → apply → validate → rollback / close) |
| `inventory_catalog` (matview) | Dedupe'd rollup the portal pulls |

### Portal side (operator's `portal` PG database)

Lives in the Customer Portal codebase. Schemas land alongside the existing `compliance_results` reader.

| Table | Purpose |
|-------|---------|
| `tenants` | Customer identity, tier, contact, AAC URL, AAC inventory pull credentials |
| `tenant_tokens` | Per-tenant credential pairs for the AAC ↔ portal pull APIs |
| `tenant_inventory_catalog` | Cached copy of each tenant's catalog (pulled nightly from their AAC) |
| `tenant_enrollments` | Coarse: which buckets each tenant cares about |
| `tenant_vendor_subscriptions` | Fine: which vendors within enrolled buckets |
| `tenant_filter_preferences` | Severity thresholds, KEV-auto-apply toggle, opt-outs |
| `feed_sources` | Operator-managed feed configuration |
| `cve_events` | Normalized CVE records from all feeds |
| `cve_bucket_tags` | CVE × bucket classification |
| `cve_vendor_tags` | CVE × vendor classification |
| `cve_artifacts` | S3 artifact metadata (bucket, key, sha256, redistributable flag) |
| `tenant_artifact_deliveries` | Delivery + acknowledgment log |
| `buckets` | Operator-curated taxonomy ("RHEL", "Windows Server", "Network", ...) |
| `vendors` | Operator-curated vendor catalog ("Red Hat", "Microsoft", "Cisco", ...) |

---

## Tenant identity flow

Operator-issued credential pair, paste-into-AAC onboarding:

1. Operator creates `tenants` row in portal → portal generates `tenant_id` (UUID) + token pair (`token_id`, `token_secret`)
2. Operator delivers credentials to customer out-of-band
3. Customer admin pastes into AAC's "Connect to Portal" UI → writes to `aac_instance_config`
4. AAC validates by calling portal's `GET /api/portal/v1/whoami`
5. From then on:
   - Portal pulls `GET https://<aac>/api/aac/v1/inventory_catalog` with the token pair
   - AAC's EDA polls `GET https://portal/api/portal/v1/tenants/<id>/cves?since=<ts>` with the same token pair

Mutual auth via shared token (HMAC) or per-tenant signed JWT. TLS required.

---

## Build order

| # | Piece | Repo | Status |
|---|-------|------|--------|
| 1 | AAC schema migration | compliance | **done** (`feat/cve-portal-integration`) |
| 2 | AAC inventory collector | compliance | in progress |
| 3 | AAC inventory API endpoint | portal (mounted on customer's AAC install) | pending |
| 4 | Portal: tenant + token onboarding | portal | pending |
| 5 | Portal: feed adapters (NVD + KEV) | portal | pending |
| 6 | Portal: bucket + vendor classification | portal | pending |
| 7 | Portal: matching engine | portal | pending |
| 8 | Portal: per-tenant CVE feed API | portal | pending |
| 9 | AAC: `lab.eda.aac_portal_feed` plugin | compliance | pending |
| 10 | AAC: CVE workflow library | compliance | pending |
| 11 | AAC: My Products UI | portal | pending |

Pieces 1–3 unlock the portal building. Pieces 5–8 unlock customer-side workflows. Pieces 9–10 close the loop end-to-end.

---

## Open items / deferred decisions

| Topic | Decision | Owner |
|-------|----------|-------|
| Patch binary signing scheme | Deferred to portal Phase 2 — operator signs binaries before serving | Portal |
| Air-gap delivery mechanism | Deferred — media drops vs. signed S3 sync | Premium-tier scope |
| Custom product CPE generation | Manual declaration only for v1 — automated CPE matching for custom apps in Phase 2 | AAC |
| Multi-region S3 / CloudFront | Single region for v1; CloudFront layer added when latency complaints surface | Portal |
| Tenant self-serve sign-up | Operator-provisioned only for v1; self-serve later | Portal |
