# AAC Customer Portal — SaaS / Cloud Services SLA Monitoring Design

**Audience:** Internal planning — engineering, product, customer success, security review.
**Purpose:** Design specification for **Piece 22 / Task #48** — monitor whether the customer's contracted cloud and SaaS providers are meeting their SLAs. Provide breach detection, time-and-impact tracking, credit-claim packet generation, and audit-report integration. MVP covers AWS, Azure, GCP, IBM Cloud + ServiceNow, Salesforce; roadmap covers the common-SaaS long tail.
**Drafted:** 2026-06-03
**Version:** v1.0

## Revision history

| Version | Date | Change |
|---|---|---|
| v1.0 | 2026-06-03 | Initial design. Per-vendor health adapters (AWS Health, Azure Service Health, GCP Status, IBM Cloud Status, ServiceNow Now Platform Status, Salesforce Trust). Customer SLA contract storage. Breach detection on operator-side polling + optional customer-side synthetic probes. Credit-claim packet generator. Integration with Phase 7 audit reports + compliance frameworks. Phased rollout: cloud providers first, then SaaS, then long tail. |

---

## 0. Guiding principle — measurable first, continued

> **Vendor SLA monitoring is squarely in the measurable camp.**
> Vendor health status is objectively observable. Breaches are
> measurable in time (start, end, duration). SLA targets are
> contractual and numeric (99.9% uptime, 4-hour response). Credit
> amounts are formulaic (% of monthly fee per breach tier). No
> process attestations are needed.

This design follows the same architectural patterns that worked for
Phases 1-7:

- **Adapter pattern per vendor** — same as remediation per-vendor role library
- **Hybrid data collection** — vendor APIs (cheapest, authoritative for self-reported) + optional customer-side probes (ground truth for actual experience)
- **Confidence + provenance tagging** — every breach record carries source + confidence
- **Signed evidence** — breach records signed by Portal so they're admissible in audit reports + vendor credit claims

---

## 1. Where this sits in the broader Portal

The Portal's existing functions answer:

- *"Is my infrastructure compliant?"* — Phases 1-4 (Rego + assessment)
- *"How do I fix gaps?"* — Phase 5 (remediation)
- *"How do I make new systems compliant?"* — Phase 6 (golden images)
- *"How do I prove all of this to an auditor?"* — Phase 7 (audit reports)

SLA monitoring answers a separate but related question:

> *"Are my vendors meeting their commitments to me?"*

This question matters because:

1. **Compliance frameworks require it.** SOC 2 CC9 (Risk Mitigation) includes vendor risk; ISO 27001 A.5.21–23 require supplier monitoring; NIST 800-53 SA-12 requires supply-chain risk management. The customer's audit needs vendor-monitoring evidence.

2. **Operational risk is real.** AWS US-EAST-1 outages have taken down thousands of dependent businesses. When the vendor breaches SLA, the customer suffers business impact. Knowing about it in real time matters.

3. **Money is at stake.** Vendor SLAs typically include credit clauses (5%–25% of monthly fee per breach tier). Most customers don't claim because tracking is hard. The Portal makes this automatic.

```
                                  ┌────────────────────────────────┐
                                  │ Customer's vendors             │
                                  │  AWS / Azure / GCP / IBM Cloud │
                                  │  ServiceNow / Salesforce / ... │
                                  └─────────────┬──────────────────┘
                                                │
                                  ┌─────────────▼──────────────────┐
                                  │ Per-vendor health endpoints    │
                                  │  status.aws.amazon.com         │
                                  │  status.azure.com              │
                                  │  status.cloud.google.com       │
                                  │  cloud.ibm.com/status          │
                                  │  status.servicenow.com         │
                                  │  trust.salesforce.com          │
                                  │  ...                           │
                                  └─────────────┬──────────────────┘
                                                │ HTTPS polling (operator-side)
   ┌──────────────────────────────────────────────────────────────────┐
   │ PORTAL (FastAPI)                                                 │
   │                                                                  │
   │  ┌──────────────────────────────┐                                │
   │  │ Per-vendor adapters          │                                │
   │  │  aws_adapter.py              │                                │
   │  │  azure_adapter.py            │                                │
   │  │  gcp_adapter.py              │                                │
   │  │  ibm_cloud_adapter.py        │                                │
   │  │  servicenow_adapter.py       │                                │
   │  │  salesforce_adapter.py       │                                │
   │  └──────────────┬───────────────┘                                │
   │                 │ writes                                         │
   │  ┌──────────────▼───────────────┐  ┌─────────────────────────┐   │
   │  │ vendor_health_observations   │◄─┤ Customer synthetic       │   │
   │  │  (per region, per service,   │  │ probes (optional)        │   │
   │  │   per time bucket)           │  │  Bridge-side or external │   │
   │  └──────────────┬───────────────┘  │  probe-as-a-service      │   │
   │                 │                  └─────────────────────────┘   │
   │  ┌──────────────▼───────────────┐                                │
   │  │ Breach detector              │                                │
   │  │  - Per-tenant SLA contract   │                                │
   │  │  - Matches observations →    │                                │
   │  │    breach events             │                                │
   │  └──────────────┬───────────────┘                                │
   │                 │ writes                                         │
   │  ┌──────────────▼───────────────┐    ┌─────────────────────┐     │
   │  │ vendor_sla_breaches          │    │ Credit calculator   │     │
   │  │                              │    │  Generates signed   │     │
   │  │  - start_at / end_at         │───▶│  credit-claim       │     │
   │  │  - duration                  │    │  packet per breach  │     │
   │  │  - affected services         │    └─────────────────────┘     │
   │  │  - calculated impact         │                                │
   │  └──────────────┬───────────────┘                                │
   │                 │                                                │
   │  ┌──────────────▼─────────────┐                                  │
   │  │ Customer-facing surfaces   │                                  │
   │  │  - Real-time dashboard     │                                  │
   │  │  - SLA breach feed         │                                  │
   │  │  - Credit-claim packets    │                                  │
   │  │  - Audit report § (Ph 7)   │                                  │
   │  └────────────────────────────┘                                  │
   └──────────────────────────────────────────────────────────────────┘
```

---

## 2. What we monitor and how

For every customer-declared vendor service, we collect three classes
of data:

| Data class | Source | Authority | Cost |
|---|---|---|---|
| **Vendor-reported health** | Vendor's published status API / RSS | Authoritative-for-self-reported; often optimistic | Cheap (operator-side) |
| **Customer's experience** | Customer-side synthetic probes (optional) | Authoritative for the customer's actual experience | Customer-installed; per-probe cost |
| **Vendor incident detail** | Vendor's incident reports + post-incident analysis | Authoritative-after-the-fact; useful for verification | Cheap (operator-side) |

The Portal stores all three. Detection runs on either class —
breach is declared if either says the service was down.

### 2.1 Polling cadence per vendor

| Cadence | Suitable for |
|---|---|
| Every 60 seconds | High-volume cloud regions (AWS US-EAST-1, Azure East US, GCP us-central1) — where every minute of downtime is material |
| Every 5 minutes | Standard cadence for most vendor health endpoints; respects rate limits |
| Every 15 minutes | Vendor APIs with strict rate limits (Salesforce Trust at peak times) |
| Webhook / push | When vendor publishes one (Azure Service Health webhook, AWS Health Events) — preferred when available |

Adapter declares its own cadence per the vendor's published rate
limit. Operator can override per-tenant if customer has a tighter
SLA they want measured.

---

## 3. Cloud provider adapters

### 3.1 AWS — `aws_health_adapter`

**Source:** AWS Health API (`https://health.aws.amazon.com/health/...`) — programmatic access via the AWS SDK; AWS Health Dashboard RSS feed (public, no auth required) as a fallback for general region status.

**Auth:** The Portal authenticates with operator-managed AWS account; **does NOT** require customer's AWS credentials. We poll the public AWS Health Dashboard (`status.aws.amazon.com/rss/all.rss`) for region-level status and AWS Health API for tenant-specific events when we have customer authorization.

**Data captured per observation:**
- Service (e.g. `AmazonEC2`, `AmazonS3`, `AWSLambda`)
- Region (e.g. `us-east-1`, `eu-west-2`)
- Status (`operating_normally`, `service_degradation`, `service_outage`)
- Event start / end timestamps
- Affected resources (when known — usually per-event detail)
- AWS event ARN (for cross-ref to Health Dashboard)

**Customer per-account integration (optional):** Customer grants Portal IAM role with `health:DescribeEvents`, `health:DescribeAffectedEntities`. Lets the Portal get per-account event detail — e.g., "your specific EC2 instances were affected."

### 3.2 Azure — `azure_service_health_adapter`

**Source:** Azure Service Health API + Azure status RSS feed (`https://status.azure.com/en-us/status/feed/`). Per-subscription detail via Azure Resource Health API.

**Auth:** Public RSS for region status; per-subscription detail requires customer's Azure AD app registration with `Microsoft.ResourceHealth/availabilityStatuses/read`.

**Data captured per observation:**
- Service (e.g., `Azure SQL Database`, `Azure Functions`, `Storage`)
- Region (e.g., `East US`, `West Europe`)
- Health state (`Available`, `Degraded`, `Unavailable`)
- Event window
- Tracking ID + Azure incident ID (for cross-ref)

### 3.3 GCP — `gcp_status_adapter`

**Source:** GCP Cloud Status Dashboard JSON feed (`https://status.cloud.google.com/incidents.json`). Per-project detail via Cloud Asset Inventory + Service Health API.

**Auth:** Public for region status. Per-project detail requires customer's GCP service account with `cloudasset.assets.searchAllResources` + `serviceusage.services.use`.

**Data captured per observation:**
- Service (e.g., `Compute Engine`, `Cloud Storage`, `BigQuery`)
- Region (e.g., `us-central1`, `europe-west1`)
- Status (`OPERATING`, `LIMITED_AVAILABILITY`, `MAJOR_OUTAGE`)
- Incident detail link + status timeline

### 3.4 IBM Cloud — `ibm_cloud_status_adapter`

**Source:** IBM Cloud Status API (`https://cloud.ibm.com/status/api/notifications`) + RSS feed.

**Auth:** Public for general status. Customer-specific events via IBM Cloud IAM API key with `read` access to Platform Health service.

**Data captured per observation:**
- Service / Component (e.g., `IBM Cloud Object Storage`, `Watson Assistant`, `IBM Cloud Functions`)
- Region (e.g., `us-south`, `eu-de`)
- Severity (`announcement`, `advisory`, `incident`, `outage`)
- Event window
- IBM notification ID + service maintenance window flag (distinguishes scheduled from unscheduled)

### 3.5 Cross-cloud observations

The four cloud adapters share a common observation schema:

```python
@dataclass
class VendorHealthObservation:
    vendor: str             # 'aws', 'azure', 'gcp', 'ibm_cloud'
    service: str            # vendor-specific service identifier
    region: str             # vendor-specific region identifier
    status: HealthStatus    # normalized: OPERATING | DEGRADED | OUTAGE
    observed_at: datetime
    event_start: datetime | None  # When the incident began
    event_end: datetime | None    # None if still ongoing
    vendor_incident_id: str | None
    vendor_incident_url: str | None
    detail_json: dict       # Raw vendor-specific detail for forensic
    polled_via: str         # 'public_rss', 'authenticated_api', 'webhook_push'
    confidence: float       # 0-1 (RSS=0.7, API=0.95, webhook=1.0)
```

The breach detector (§5) operates on this normalized form regardless
of source vendor.

---

## 4. SaaS service adapters

### 4.1 ServiceNow — `servicenow_status_adapter`

**Source:** ServiceNow Now Platform Status (`https://status.servicenow.com/api/status.json`) + RSS feed. Customer-instance detail via the customer's own Now instance via REST API.

**Auth:** Public for general platform status; customer-instance detail requires customer-provided ServiceNow API credentials with `read` on `sys_user_admin` scope (Portal queries the customer's instance health endpoints).

**Data captured per observation:**
- Instance / data center (e.g., `salt-lake-1`, `frankfurt-1`)
- Service (e.g., `Now Platform`, `Virtual Agent`, `Knowledge`)
- Status (`operational`, `degraded`, `partial_outage`, `major_outage`, `under_maintenance`)
- Event window + ServiceNow incident URL

**SaaS-specific consideration:** ServiceNow customers often have dedicated instances. The status page may show the platform as healthy while a specific customer instance has problems. Best practice: cross-check public status + customer instance health (if Portal has API access to the customer's instance).

### 4.2 Salesforce — `salesforce_trust_adapter`

**Source:** Salesforce Trust API (`https://api.status.salesforce.com/v1/...`) — REST endpoints for instance / service status. Per-customer-instance detail via the customer's Salesforce org Apex API.

**Auth:** Public for general status; per-org detail requires customer's Salesforce OAuth token with `api` scope.

**Data captured per observation:**
- Instance (e.g., `NA1`, `EU3`, `AP4`)
- Service (e.g., `Core Platform`, `Search`, `Database`, `Reporting`)
- Status (`available`, `degraded_performance`, `service_disruption`, `major_disruption`)
- Maintenance window flag (Salesforce announces planned maintenance via the Trust API; we don't count these toward SLA breaches)

### 4.3 Roadmap — additional SaaS adapters

Same architectural pattern; add as customers request. Priority based on enterprise adoption:

| Adapter | Vendor service | Phase |
|---|---|---|
| `m365_service_health_adapter` | Microsoft 365 Service Health (already in scope per `policy_ingestion_design.md` M365 work) | Phase 1 |
| `okta_trust_adapter` | Okta Trust (`trust.okta.com`) | Phase 2 |
| `atlassian_status_adapter` | Atlassian Status (Jira, Confluence) | Phase 2 |
| `workday_status_adapter` | Workday Community Status | Phase 2 |
| `github_status_adapter` | GitHub Status (Enterprise Cloud + standard) | Phase 2 |
| `slack_status_adapter` | Slack Status | Phase 2 |
| `zoom_status_adapter` | Zoom Service Status | Phase 2 |
| `box_status_adapter` | Box Status | Phase 3 |
| `dropbox_status_adapter` | Dropbox Business Status | Phase 3 |
| `snowflake_status_adapter` | Snowflake Status | Phase 3 |
| `datadog_status_adapter` | Datadog Status (yes, even the observability vendors monitor themselves) | Phase 3 |
| `oracle_cloud_status_adapter` | Oracle Cloud Infrastructure Status | Phase 3 |
| `sap_status_adapter` | SAP Cloud Status | Phase 3 |
| `twilio_status_adapter` | Twilio Status | Phase 3 |
| `stripe_status_adapter` | Stripe Status | Phase 3 |

### 4.4 Generic webhook adapter

For vendors without published health endpoints (or for customers
running internal services they want monitored), the Portal accepts
inbound webhook observations:

`POST /api/portal/v1/tenants/{id}/sla/observations/webhook`

Lets the customer post their own observations (from internal
monitoring) into the same data model. Treats webhook submissions as
authoritative for the customer's perspective.

---

## 5. Customer SLA contract storage

The Portal needs to know what SLA terms the customer has with each
vendor before breaches can be detected. Three sources, in priority
order:

### 5.1 Customer-uploaded contract (preferred)

Customer uploads their MSA / SLA addendum (PDF / docx). Portal
extracts via the same parser used for policy ingestion (Path A in
`policy_ingestion_design.md`). LLM IR extraction adapted for SLA
terms:

```json
{
  "vendor": "aws",
  "contract_version": "v2.3",
  "effective_date": "2026-04-01",
  "expiry_date": "2027-03-31",
  "service_levels": [
    {
      "service": "AmazonEC2",
      "scope": "running compute instances",
      "uptime_target_pct": 99.99,
      "measurement_window": "monthly_billing_cycle",
      "exclusions": ["scheduled_maintenance_announced_72h_in_advance", "force_majeure"],
      "credit_tiers": [
        {"availability_below_pct": 99.99, "credit_pct_of_monthly_fee": 10},
        {"availability_below_pct": 99.00, "credit_pct_of_monthly_fee": 25},
        {"availability_below_pct": 95.00, "credit_pct_of_monthly_fee": 100}
      ]
    },
    ...
  ]
}
```

Customer reviews + approves the extracted IR before it goes live (same
review pattern as policy ingestion).

### 5.2 Vendor-published default SLA

When the customer hasn't uploaded a contract, the Portal uses the
vendor's published default SLA as a baseline. We curate these in a
shared `vendor_default_slas` table; refresh quarterly per vendor's
public terms.

| Vendor | Default SLA reference |
|---|---|
| AWS | `aws.amazon.com/legal/service-level-agreements/` |
| Azure | `azure.microsoft.com/en-us/support/legal/sla/` |
| GCP | `cloud.google.com/terms/sla/` |
| IBM Cloud | `cloud.ibm.com/docs/overview?topic=overview-slas` |
| ServiceNow | `servicenow.com/customers/customer-success-trust` (varies by contract) |
| Salesforce | `salesforce.com/company/legal/agreements/` |

### 5.3 Industry-standard fallback

If neither customer contract nor vendor default is available, the
Portal uses a conservative industry-standard fallback (99.9% monthly
uptime, no credits) so breaches can still be detected even without
contract data.

---

## 6. Breach detection

### 6.1 Detection rule

For each (tenant × vendor × service × region) combination:

```python
def detect_breaches(tenant_id, vendor, service, region, window_start, window_end):
    contract = load_sla_contract(tenant_id, vendor, service)
    observations = query_observations(vendor, service, region, window_start, window_end)

    # Sum unavailable time in window, excluding contractual exclusions
    unavailable_seconds = 0
    for obs in observations:
        if obs.status != HealthStatus.OPERATING:
            if not is_excluded(obs, contract.exclusions):
                unavailable_seconds += duration(obs)

    window_seconds = (window_end - window_start).total_seconds()
    actual_availability_pct = 1 - (unavailable_seconds / window_seconds)
    target = contract.uptime_target_pct

    if actual_availability_pct < target:
        breach = VendorSlaBreach(
            tenant_id=tenant_id,
            vendor=vendor,
            service=service,
            region=region,
            window_start=window_start,
            window_end=window_end,
            target_availability_pct=target,
            actual_availability_pct=actual_availability_pct,
            unavailable_seconds=unavailable_seconds,
            credit_eligible=True,
            credit_tier=lookup_credit_tier(contract.credit_tiers, actual_availability_pct),
        )
        sign_with_portal_key(breach)
        emit_breach_event(breach)
```

### 6.2 Detection cadence

| Window | Detection runs |
|---|---|
| Real-time / current incident | Every minute (light query against open observations) |
| Hourly rolling | Every 5 minutes |
| Daily rolling | Hourly |
| Monthly billing cycle | Daily + at billing cycle close |
| Annual | Monthly + at year close |

The Portal maintains running summaries to make these queries cheap.

### 6.3 Notification routing

Per-tenant notification preferences:

| Severity | Default notification recipients |
|---|---|
| **Critical** (vendor major outage in customer's primary region) | Account Owner + on-call paging (per tenant's preferred channel: PagerDuty / Opsgenie / Slack / email) |
| **High** (vendor service-level breach detected in current window) | Account Owner + Compliance Owner |
| **Medium** (breach summary at end of measurement window) | Compliance Owner + monthly digest |
| **Low** (vendor scheduled maintenance announcement) | Information only; available on dashboard |

---

## 7. Credit calculation + claim packet generation

The highest-leverage feature beyond raw monitoring: turning detected
breaches into vendor credit claims the customer can actually submit.

### 7.1 Credit calculation

For each detected breach, the Portal calculates:

```python
def calculate_credit(breach, contract, monthly_fee):
    tier = lookup_credit_tier(contract.credit_tiers, breach.actual_availability_pct)
    credit_pct = tier.credit_pct_of_monthly_fee
    credit_amount = monthly_fee * (credit_pct / 100)
    return credit_amount, tier
```

Customer supplies their monthly fee per service (private, only used
for calculation). The Portal computes credit amount + breach summary.

### 7.2 Credit-claim packet

Generated as a signed evidence bundle, deliverable to the vendor's
customer support / account team:

```
acme-corp-aws-credit-claim-2026-04.pdf  (signed)
├── Section 1: Breach summary
│   - Service, region, window
│   - Actual vs target availability
│   - Calculated credit amount
├── Section 2: Evidence
│   - Vendor's own status page observations (with screenshots)
│   - Vendor's incident IDs + post-mortem links
│   - Portal's polling logs (signed)
│   - (Optional) Customer-side synthetic probe results
├── Section 3: Contract reference
│   - Excerpt of customer's SLA terms
│   - Specific credit clause cited
├── Section 4: Customer signature + submission contact
└── Portal signature for chain of custody
```

The customer reviews + signs (with their Account Owner MFA-asserted
identity) + submits to the vendor through their standard account
management process.

### 7.3 Tracking through to credit issuance

The customer marks each claim as `submitted`, `vendor_acknowledged`,
`vendor_disputed`, `credited`, or `denied`. The Portal tracks the
full lifecycle:

- Submission date + recipient
- Vendor response date + outcome
- Credit applied (amount, billing cycle)
- Disputes + resolutions

This timeline becomes evidence for audit reports (§8 below).

---

## 8. Integration with audit reports (Phase 7)

SLA monitoring evidence belongs in audit reports under multiple
control families:

### 8.1 SOC 2 evidence — CC9 (Risk Mitigation) + A1.2 (Availability)

The customer can include in their SOC 2 report:

- *"We monitor vendor SLAs continuously. The following table summarizes vendor uptime over the audit window."* → table from Portal data
- *"Vendor SLA breaches and their disposition during the audit window:"* → list from `vendor_sla_breaches`
- *"Credit claims submitted to vendors and outcomes:"* → from claim tracking
- *"Our vendor portfolio risk assessment:"* → cross-vendor uptime aggregate

### 8.2 ISO 27001 evidence — A.5.21 (ICT Supply Chain), A.5.22 (Vendor Monitoring)

Provides continuous monitoring data the auditor expects:

- Vendor service catalog + contracts (from `tenant_vendor_subscriptions`)
- Monitoring frequency + methodology (Portal's polling cadence)
- Detected issues + remediation (vendor SLA breaches + claim outcomes)
- Vendor reassessment cadence (Portal flags vendor service degradation patterns)

### 8.3 NIST 800-53 evidence — SA-12 (Supply Chain), CP-6 (Alternate Storage), SC-5 (DoS Protection)

For federal customers — Portal's SLA monitoring is direct evidence
for these controls.

### 8.4 Continuous control monitoring (CCM)

Some auditors (especially Big Four engagements) require continuous
control monitoring evidence rather than point-in-time samples. The
SLA monitoring is naturally continuous — daily/hourly granularity
satisfies CCM requirements.

---

## 9. Integration with the compliance loop

### 9.1 Connection to remediation playbooks (Phase 5)

When a vendor SLA breach materially affects the customer's
infrastructure, the Portal can trigger remediation playbooks
designed for vendor-failure scenarios:

| Vendor failure | Remediation playbook (Phase 5) |
|---|---|
| AWS region outage | Fail over to secondary region (Backup → Patch → Validate adapted) |
| Azure AD outage | Switch to break-glass local-auth procedure |
| GCP storage outage | Switch to on-prem backup tier |
| Salesforce major disruption | Switch to read-only cache mode |
| ServiceNow outage | Activate manual incident workflow |

These remediation playbooks have the same Backup → Patch → Validate
contract; the IR drives the playbook for vendor-dependent business
processes.

### 9.2 Connection to baselining (Piece 50)

The Portal tracks per-vendor SLA performance over time. Baseline
snapshots include vendor SLA achievement %. Lets the customer say
*"our vendor SLA achievement was X% in Q1 2026 vs Y% in Q2 2026."*

### 9.3 Connection to technical-debt heat map (Piece 51)

Vendor SLA breaches that lead to mitigation expense are tech debt
the customer is paying. Surface in the heat map.

### 9.4 Connection to GRC platforms

The same delivery adapters built for Phase 7 audit reports
(Drata, Vanta, OneTrust, AuditBoard) push SLA monitoring evidence
to the customer's GRC vendor risk management modules.

---

## 10. Data model

### `tenant_vendor_subscriptions`

What vendor services each tenant cares about.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | FK |
| `vendor` | text | `aws`, `azure`, `gcp`, `ibm_cloud`, `servicenow`, `salesforce`, ... |
| `service` | text | Vendor-specific (e.g., `AmazonEC2`) |
| `region` | text | Vendor-specific |
| `monthly_fee_usd` | decimal | Customer-supplied, for credit calc |
| `monthly_fee_currency` | text | Default USD |
| `subscription_started_at` | date | |
| `subscription_status` | enum | `active`, `paused`, `terminated` |
| `created_at` | timestamptz | |

### `vendor_sla_contracts`

Customer's SLA terms per vendor.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | FK |
| `tenant_vendor_subscription_id` | uuid | FK (nullable — can apply across multiple subscriptions) |
| `vendor` | text | |
| `source` | enum | `customer_uploaded`, `vendor_default`, `industry_fallback` |
| `contract_storage_key` | text | Object-store ref to the original document if uploaded |
| `contract_sha256` | text | Integrity check |
| `extracted_ir_json` | jsonb | LLM-extracted IR of contract terms |
| `effective_date` | date | |
| `expiry_date` | date | nullable |
| `status` | enum | `draft`, `published`, `expired`, `archived` |

### `vendor_health_observations`

Per-poll observation data. High volume — partition by month.

| Column | Type | Notes |
|---|---|---|
| `id` | bigserial | PK |
| `vendor` | text | |
| `service` | text | |
| `region` | text | |
| `status` | text | normalized HealthStatus |
| `observed_at` | timestamptz | indexed |
| `event_start` | timestamptz | nullable |
| `event_end` | timestamptz | nullable — null means still ongoing |
| `vendor_incident_id` | text | nullable |
| `vendor_incident_url` | text | nullable |
| `detail_json` | jsonb | raw vendor-specific |
| `polled_via` | text | source |
| `confidence` | float | 0-1 |
| `is_excluded_event` | bool | scheduled maintenance, etc. |

### `vendor_sla_breaches`

Detected breach events. One row per breach window per tenant per
service per region.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | FK |
| `vendor` | text | |
| `service` | text | |
| `region` | text | |
| `vendor_sla_contract_id` | uuid | FK |
| `window_start` | timestamptz | |
| `window_end` | timestamptz | |
| `target_availability_pct` | float | |
| `actual_availability_pct` | float | |
| `unavailable_seconds` | int | |
| `credit_tier_idx` | int | which credit tier hit |
| `credit_eligible` | bool | |
| `calculated_credit_amount_usd` | decimal | nullable |
| `breach_signature` | text | Portal signature for evidence |
| `detected_at` | timestamptz | |

### `vendor_sla_credit_claims`

Customer's claim submissions + outcomes.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | FK |
| `vendor_sla_breach_id` | uuid | FK |
| `claim_packet_storage_key` | text | Signed PDF location |
| `submitted_at` | timestamptz | nullable until customer submits |
| `submitted_by_user_id` | uuid | nullable |
| `vendor_response_at` | timestamptz | nullable |
| `vendor_response` | enum | `acknowledged`, `disputed`, `credited`, `denied` |
| `actual_credit_received_usd` | decimal | nullable |
| `applied_to_billing_cycle` | text | nullable |
| `closed_at` | timestamptz | nullable |
| `notes` | text | |

---

## 11. API surface

### Customer-facing

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/portal/v1/tenants/{id}/vendor-subscriptions` | List declared vendor subscriptions |
| POST | `/api/portal/v1/tenants/{id}/vendor-subscriptions` | Declare a new vendor subscription |
| PATCH | `/api/portal/v1/tenants/{id}/vendor-subscriptions/{id}` | Update subscription details |
| POST | `/api/portal/v1/tenants/{id}/sla-contracts/upload` | Upload SLA contract (multipart) |
| GET | `/api/portal/v1/tenants/{id}/sla-contracts/{id}/ir` | Get extracted IR for customer review |
| POST | `/api/portal/v1/tenants/{id}/sla-contracts/{id}/publish` | Publish reviewed contract |
| GET | `/api/portal/v1/tenants/{id}/sla-status` | Current SLA status across all vendors |
| GET | `/api/portal/v1/tenants/{id}/sla-status/{vendor}/{service}/{region}` | Detail status for one combination |
| GET | `/api/portal/v1/tenants/{id}/sla-breaches` | Historical breaches with filters (window, vendor) |
| GET | `/api/portal/v1/tenants/{id}/sla-breaches/{id}` | Detail view with all evidence |
| POST | `/api/portal/v1/tenants/{id}/sla-breaches/{id}/credit-claim` | Generate credit-claim packet |
| GET | `/api/portal/v1/tenants/{id}/sla-credit-claims` | List + status |
| PATCH | `/api/portal/v1/tenants/{id}/sla-credit-claims/{id}` | Update with vendor response |
| POST | `/api/portal/v1/tenants/{id}/sla/observations/webhook` | Generic webhook intake |

### Operator-side

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/admin/v1/vendor-adapters` | List adapter status (last poll, errors, rate limits) |
| POST | `/api/admin/v1/vendor-adapters/{vendor}/refresh-defaults` | Refresh vendor default SLAs from public terms |
| GET | `/api/admin/v1/vendor-observations` | Cross-tenant observation feed for diagnostics |

---

## 12. Frontend pages

| Route | Purpose |
|---|---|
| `/sla` | Dashboard — current status per vendor + recent breaches + open claims |
| `/sla/vendors` | List of declared vendor subscriptions with management actions |
| `/sla/vendors/new` | Add a new vendor subscription wizard |
| `/sla/contracts` | List of uploaded SLA contracts |
| `/sla/contracts/upload` | Upload + review workflow |
| `/sla/breaches` | Historical breach feed with filters |
| `/sla/breaches/{id}` | Detail view: evidence, credit calc, packet preview |
| `/sla/claims` | Credit-claim lifecycle tracking |
| `/sla/reports` | Aggregate analysis (vendor portfolio risk view) |

---

## 13. Failure modes

| Failure | Detection | Response |
|---|---|---|
| Vendor health endpoint returns 5xx | Adapter polling | Exponential backoff; alert at 3 consecutive failures; fall back to alternate source (RSS if API failed) |
| Vendor changes their status page format | Schema validator at adapter | Adapter marks polling as `degraded`; operator notified; legacy data still queryable |
| Vendor publishes false "operational" status during an outage | Cross-check with synthetic probe (if enabled) or customer reports | Treat as breach if probe disagrees; flag for operator review |
| Customer SLA contract IR extraction is incorrect | Customer review step (mirrors policy ingestion review) | Customer corrects IR; Portal re-publishes |
| Breach detection has false positive (vendor reported outage that didn't actually affect customer) | Customer can mark breach as `not_applicable_to_my_usage` | Breach record retained for audit; customer's claim packet only includes confirmed-applicable breaches |
| Credit calculation discrepancy with vendor | Customer disputes; tracked in claim lifecycle | Update credit_claim records with vendor's revised calculation; capture rationale |
| Portal-side polling job crash | Internal monitoring (operations runbook §1) | Job restarts; observation gap flagged in next breach calculation |

---

## 14. Open questions

| # | Question | Default for MVP |
|---|---|---|
| 1 | Customer-side synthetic probes — Portal-supplied probe-as-a-service or customer-installed? | **Customer-installed** in MVP (lighter operator burden); Portal-managed probes a Phase 2 option |
| 2 | Multi-cloud aggregate view (when AWS US-EAST-1 dies + customer fails over to GCP, what does the dashboard show?) | **Per-vendor view in MVP** with cross-vendor aggregation in Phase 2 |
| 3 | Credit-claim auto-submission to vendors (vs customer-mediated) | **Customer-mediated** for MVP (legal questions about who's the submitter); auto-submission optional Phase 2 |
| 4 | Should the Portal monitor itself (Portal SLA → Portal customers)? | **Yes** — eat own dogfood. Phase 7.5. |
| 5 | Vendor portfolio risk scoring (composite across all vendors a tenant uses) | **Phase 2** — needs more data to be meaningful |
| 6 | LLM-assisted contract IR extraction confidence threshold for auto-publish | **Same as policy ingestion** — customer review required before publish |
| 7 | Generic webhook adapter — open to all tenants or rate-limited? | **Rate-limited** by tier (Free: 1 webhook/hour; Premium: 1/minute) |
| 8 | Vendor SLA terms change mid-contract (vendor publishes a new SLA version) | **Customer notified**; existing contract continues until customer reviews + approves new version |
| 9 | Region-specific contract terms (some customers have different SLAs per region) | **Modeled as separate vendor_sla_contract rows** linked to subscription per region |
| 10 | Backfill historical data when customer first onboards | **30 days backfill from public RSS** (best-effort); full history requires customer credentials for vendor-specific APIs |

---

## 15. Phased implementation plan

### Phase 1 — cloud providers (sprints 1-2)

1. Data model + migrations
2. Adapter framework: `VendorAdapter` interface, registry, scheduler
3. Four cloud adapters: `aws_health`, `azure_service_health`, `gcp_status`, `ibm_cloud_status`
4. Customer SLA contract upload + IR extraction (reuses policy ingestion stack)
5. Breach detector
6. Customer-facing dashboard MVP

### Phase 2 — SaaS services (sprints 3-4)

7. Two flagship SaaS adapters: `servicenow_status`, `salesforce_trust`
8. Generic webhook adapter
9. Credit-claim packet generator + signing
10. Credit-claim lifecycle tracking
11. Notification routing per tenant preferences

### Phase 3 — long tail + integration (sprints 5-6)

12. Common SaaS adapters: M365 (existing), Okta, Atlassian, Workday, GitHub, Slack, Zoom
13. Integration with Phase 7 audit reports (SOC 2 / ISO 27001 / NIST 800-53 evidence sections)
14. Integration with Phase 5 remediation (vendor-failure playbooks)
15. GRC platform delivery adapters (Drata, Vanta, OneTrust vendor risk modules)
16. End-to-end soak test

### Phase 4 — advanced features (sprints 7+)

17. Cross-vendor aggregate views
18. Portal-managed synthetic probes
19. Auto-submission to vendors (per customer opt-in)
20. Long-tail SaaS adapters (Phase 3 table in §4.3)

---

## 16. References

### Builds on / depends on

- `policy_ingestion_design.md` — Path A IR extraction (reused for SLA contracts) + customer review patterns
- `remediation_generator_design.md` — same adapter pattern + signed evidence model
- `audit_reports_design.md` — SLA monitoring evidence section in Phase 7 reports
- `portal_capabilities_brief.md` §1.5 (SaaS/Cloud SLA Monitoring) + Piece 22

### Vendor health endpoints (verified at design time)

- AWS Health Dashboard + Health API
- Azure Service Health + Resource Health API
- GCP Cloud Status Dashboard JSON feed
- IBM Cloud Status API
- ServiceNow Now Platform Status
- Salesforce Trust API
- Microsoft 365 Service Health (existing AAC integration)

### Standards referenced

- **SOC 2 Trust Services Criteria** — CC9 (Risk Mitigation), A1.2 (Availability)
- **ISO 27001:2022** — A.5.21 (ICT Supply Chain), A.5.22 (Vendor Monitoring)
- **NIST SP 800-53 Rev 5** — SA-12 (Supply Chain), CP-6 (Alternate Storage), SC-5 (DoS Protection)

---

**Authored with Claude (Anthropic).**
