# AAC Customer Portal — Operations Runbook

**Audience:** Internal planning — engineering, SRE, ops, leadership.
**Purpose:** Define the day-to-day operating practices required to keep
the Portal running once it's in production. This is the **tactical**
companion to the four strategic documents in this folder:

- `portal_saas_lens_assessment.md` — what's architecturally right or wrong
- `portal_security_baseline.md` — what's secure or not
- `portal_reliability_slo.md` — what we promise and measure
- `portal_competitive_benchmark.md` — what peers do
- **`portal_operations_runbook.md` ← you are here** — **how we run it**

**Drafted:** 2026-06-02
**Version:** v1.0

## Revision history

| Version | Date | Change |
|---|---|---|
| v1.0 | 2026-06-02 | Initial full content pass — twelve operational domains with current state + recommended approach + maturity-phase tagging. |

---

## How this relates to the other four documents

The strategic docs identify gaps. This doc defines how a real operating
team works around them and closes them. Specifically:

| Gap from another doc | Operations behavior that addresses it |
|---|---|
| A1 gap O1 (per-tenant observability) | §1 below — defines the metrics + logging conventions |
| A1 gap R1 (no rate limiter) | §3 below — incident playbook covers "noisy tenant" until R1 lands |
| A1 gap R4 (no DR runbook) | §2 + §9 below |
| A2 (security controls) | §6 + §10 below |
| A3 (SLO targets) | §1 (monitoring of SLIs) + §3 (paging) |

---

## Operations cadence at a glance

A summary of what happens, how often, when the operations team is mature.

| Cadence | What |
|---|---|
| **Continuous** | Health monitoring, SLO burn-rate alerts, backup streaming, audit-log ingestion |
| **Daily** | Operator standup (status of overnight alerts, tenant onboards, feed runs); ticket triage; bridge-heartbeat review |
| **Weekly** | SLO review (each surface vs target); error-budget burn report; security alert review; capacity headroom check |
| **Bi-weekly** | Release window; sprint review; post-mortem reviews |
| **Monthly** | Tenant-billing reconciliation; cost-attribution review; SOC 2 evidence collection (when SOC 2 is in scope); access review |
| **Quarterly** | DR drill; game day; penetration test review; risk register update; SLO target re-baselining |
| **Annual** | SOC 2 audit; penetration test; tabletop exercise for catastrophic scenarios; ops process retrospective |

---

## 1. Monitoring & observability

### Why it matters

Without per-tenant observability, every other operations process
becomes guesswork. A customer reports "the feed is slow" and the
operator can either (a) check Surface 2's SLO dashboard and confirm
or refute, or (b) read raw logs. Only (a) scales.

### What we need

| Capability | Status | Implementation phase |
|---|---|---|
| Structured logging with `tenant_id` in every request log | ⏳ A1 gap O1 | Phase 1 — day 0–30 |
| Prometheus metrics tagged by `tenant_id`, `tier`, `endpoint`, `status_class` | ⏳ A1 gap O1 / brief Piece 30 | Phase 1 |
| Centralized log aggregation (Loki / Elastic / Splunk / Datadog) | ⏳ Not started | Phase 1 |
| Distributed tracing (OpenTelemetry) | ⏳ Not started | Phase 2 — day 30–90 |
| SLO burn-rate alerts (per A3 §change-management) | ⏳ depends on the above | Phase 2 |
| Synthetic monitoring (per-tenant probes against Surfaces 2 + 3) | ⏳ Not started | Phase 2 |
| Real User Monitoring (RUM) on the React apps | ⏳ Not started | Phase 3 — day 90–365 |
| Custom dashboards per surface (one Grafana board per Surface 1–9 in A3) | ⏳ Not started | Phase 1 (boards) → Phase 2 (alerting) |

### Recommended approach

**Phase 1 (day 0–30) — the minimum viable observability:**

1. Add a FastAPI middleware that:
   - Generates a request ID (UUIDv7 so it's roughly sortable).
   - Extracts `tenant_id` from path (if a `/portal/v1/tenants/{id}/...` route) or marks the request `tenant=__operator__`.
   - Emits a structured log line per request: `ts, request_id, tenant_id, tier, endpoint, method, status, latency_ms, bytes_in, bytes_out`.
   - Exports Prometheus counters: `portal_requests_total{tenant_id, tier, endpoint, status_class}` and histograms `portal_request_latency_seconds{...}`.
2. Drop in Loki or Elastic (or piggyback on Grafana if already deployed for AAC compliance dashboards) to ingest the logs.
3. Build one Grafana board per surface from A3 — minimum panels: per-tier SLI (availability, latency), per-tenant top-10 by request volume, error budget burn-down.

**Phase 2 (day 30–90):**

4. Add OpenTelemetry tracing — at minimum the request → DB query chain.
5. Implement burn-rate alerts per A3's change-management policy. Route to PagerDuty / OpsGenie / Slack-with-paging.
6. Stand up synthetic monitoring — one canary "tenant" per environment whose feed pull is validated end-to-end every minute.

**Phase 3 (day 90–365):**

7. RUM instrumentation in the React apps (Surface 8 in A3 depends on this for honest SLI measurement).
8. Anomaly detection on per-tenant traffic (Datadog Watchdog / Splunk SignalFx / homegrown z-score).

### Tooling options

| Layer | Open-source | Hosted SaaS |
|---|---|---|
| Metrics | Prometheus + Grafana | Datadog, New Relic, Honeycomb |
| Logs | Loki, Elasticsearch | Datadog Logs, Splunk Cloud |
| Traces | OpenTelemetry → Tempo / Jaeger | Datadog APM, Honeycomb, Lightstep |
| Synthetic | Blackbox exporter + Prometheus | Datadog Synthetic, Pingdom, StatusCake |
| RUM | Self-hosted OTel + sampling | Datadog RUM, New Relic Browser |
| Alerts | Alertmanager + PagerDuty | Datadog Monitors |

**Recommendation for the Portal:** start with the open-source stack
(Prometheus + Grafana + Loki + OpenTelemetry) because it ships with
AAC already; consolidating to a SaaS like Datadog later is feasible
once revenue justifies it. Decision can defer.

### Current state

Zero observability beyond FastAPI's default access log. Phase 1 is
the immediate next investment.

---

## 2. Backups & restore

### Why it matters

The Portal's PostgreSQL database holds tenant onboarding state, every
CVE match, every audit-evidence reference, every token. A loss-of-data
event without working backups is an extinction-level incident — both
for the Portal as a business and for customers' audit trails.

### What we need

| Capability | Status | Implementation phase |
|---|---|---|
| Continuous WAL streaming to off-site storage | ⏳ Not started | Phase 1 |
| Periodic full backups (daily) | ⏳ Likely informal | Phase 1 |
| Backup encryption at rest (off-site copy) | ⏳ Likely depends on storage default | Phase 1 |
| Backup retention policy aligned to compliance requirements (7 years for SOC 2 evidence?) | ⏳ Not formalized | Phase 2 |
| Verified backup integrity (test restore in scratch environment) | ⏳ Not done | Phase 1 |
| Selective tenant restore (A1 gap R5) | ⏳ Not started | Phase 2 |
| Cross-region backup copies | ⏳ Not started | Phase 3 |
| Backup-failure paging | ⏳ Not started | Phase 1 |

### Recommended approach

**Phase 1 (day 0–30) — never lose more than 1 hour of data:**

1. Configure PostgreSQL WAL archiving to off-site object storage (S3 / Azure Blob / GCS — encrypted at rest with a key the Portal doesn't hold, ideally a separate-cloud-account / separate-region location).
2. Schedule daily full base backups; retain 35 daily + 12 monthly + 7 yearly (cost-effective compliance retention).
3. Set up paging on backup-failure events: any 24 h without a successful backup is Sev 2.
4. Run **one test restore per month** in a scratch environment. An untested backup does not exist.

**Phase 2 (day 30–90):**

5. Build the selective-tenant restore capability (A1 R5). Given the schema is `tenant_id`-keyed, this is implementable as a per-tenant logical export from the backup that gets imported into the current schema. Requires testing because tenant-cross-referenced tables (e.g. cve matches referencing CVEs that may have been classified differently) need conflict resolution.
6. Define and document RPO/RTO targets per A3 (Surface 9). Recommended starting targets: **RPO = 1 hour, RTO = 4 hours** for tier-Premium customers (well above what a small disaster needs in practice).

**Phase 3 (day 90–365):**

7. Cross-region backup copies (for the regulated / federal tier).
8. Air-gap-capable backup snapshots delivered out-of-band for the Air-gapped tier.

### Tooling options

| Approach | Description |
|---|---|
| **Native pg_basebackup + WAL-G/wal-g/Barman** | Best-of-breed Postgres backup tooling; works on any infra |
| **Managed Postgres (RDS / Cloud SQL / Aurora)** | Provider does the backup with point-in-time recovery |
| **Storage-layer snapshots (EBS / EFS)** | Coarser RPO but very fast restore |

**Recommendation:** start with managed Postgres if the Portal is in a
public cloud (let the provider handle the operational mechanics);
self-managed pg_basebackup + WAL-G + S3 for self-hosted deployments.

### Current state

Reliant on whatever the deployment environment provides. No
documented backup procedure, no verified restore, no RPO/RTO target.
This is the **single biggest operational risk** today after rate
limiting.

---

## 3. On-call and incident response

### Why it matters

A SaaS without on-call is a SaaS that goes down on Friday night and
stays down until Monday morning. Customers who pay for an SLA need
someone to be reachable.

### What we need

| Capability | Status | Phase |
|---|---|---|
| Defined severity matrix (Sev 1–4) | ⏳ A1 gap O2 | Phase 1 |
| On-call rotation (one primary + one secondary) | ⏳ Not started | Phase 1 |
| Escalation paths (engineer → manager → director → exec) | ⏳ Not started | Phase 1 |
| Paging integration (Surface 1 → on-call) | ⏳ Depends on monitoring | Phase 1 |
| Incident channels (Slack / Teams + ad-hoc Zoom bridge) | ⏳ Not formalized | Phase 1 |
| Status page (`status.aac-portal.example`) | ⏳ Brief Piece 29 | Phase 1 |
| Customer comms cadence per severity | ⏳ Not started | Phase 1 |
| Post-mortem template + cadence | ⏳ A1 gap O5 | Phase 1 |
| Tabletop exercises | ⏳ Not started | Phase 2 |
| Game days (chaos engineering) | ⏳ A1 gap O4 | Phase 2 |

### Recommended approach

**Severity matrix:**

| Severity | Definition | Customer comms | Internal cadence |
|---|---|---|---|
| **Sev 1** | Multiple tenants affected; CVE feed delivery down; data-loss event; auth surface down | Status page updated within 15 min; customer email within 1 h | Page on-call; engage incident commander; bridge open until resolved |
| **Sev 2** | Single tenant materially affected, OR Premium-tier SLO breach imminent, OR backup failure 24 h+ | Status page updated within 1 h; affected tenant emailed within 4 h | Page on-call; resolve within business day if possible |
| **Sev 3** | Single tenant cosmetically affected, OR Standard-tier SLO breach, OR non-critical feature broken | Status page updated within 4 h | Ticket; resolve in current sprint |
| **Sev 4** | Internal-only impact (operator console down, dev environment broken) | None | Ticket; resolve in current or next sprint |

**On-call structure:**

- Two-tier rotation: primary engineer (1-week rotation), secondary engineer (1-week, offset by 0.5 weeks for handoff coverage).
- Engineering manager is the escalation point if neither responds in 15 min.
- Compensate explicitly for on-call (per-week stipend + post-shift comp time).
- Don't put a single person on call alone — even a 1-engineer team adopts a "buddy" practice with a peer team.

**Post-mortem discipline:**

- Every Sev 1 and Sev 2 gets a written post-mortem within 5 business days.
- Blameless — focuses on the system, not the engineer.
- Reviewed at bi-weekly engineering review.
- Action items tracked as tickets; reviewed in subsequent post-mortems for follow-through.

### Tooling options

| Need | Open-source | Hosted |
|---|---|---|
| Paging | Grafana OnCall, OpsGenie OSS | PagerDuty, OpsGenie, Splunk OnCall |
| Status page | Cachet, Statping | Atlassian Statuspage, Instatus, OhDear |
| Incident commander tooling | Manual (Slack channels + Google docs) | FireHydrant, incident.io, Rootly |
| Post-mortem | Confluence template, Google docs | Jeli, Blameless |

**Recommendation:** PagerDuty + Atlassian Statuspage (industry-standard
combo, integrates with everything, defensible to enterprise customers
who ask). Self-host the post-mortem template in the engineering wiki —
no tool needed.

### Current state

No on-call, no severity matrix, no status page. This is the **single
biggest operational risk** in the "what happens at 2 a.m. on a
Saturday" sense — customers paying for an SLA won't get a response
because there's no one paged.

---

## 4. Patch & maintenance management

### Why it matters

Every dependency is a potential CVE. The Portal that runs a
compliance product cannot itself be out of date.

### What we need

| Capability | Status | Phase |
|---|---|---|
| OS / container base image update cadence | ⏳ Informal | Phase 1 |
| Python dependency update cadence (pip-tools / Renovate / Dependabot) | ⏳ Not started | Phase 1 |
| Node / npm dependency update cadence | ⏳ Not started | Phase 1 |
| Postgres minor version updates | ⏳ Informal | Phase 1 |
| Postgres major version upgrades (cadence + cutover plan) | ⏳ Not formalized | Phase 2 |
| Maintenance windows announced in advance | ⏳ Not started | Phase 1 |
| Pre-prod environments to test updates | ⏳ Not formalized | Phase 1 |
| Rollback procedure documented per change category | ⏳ Not started | Phase 2 |

### Recommended approach

**Monthly maintenance window:** announce in advance (status page + tenant email), targeting a low-traffic window (e.g., Saturday 02:00 UTC). Use it for:
- OS / base image refresh
- Postgres minor version bump
- Dependency rollups
- Schema migrations that need brief downtime (although ideally zero — see expand-contract pattern in `portal_change_management.md` when written)

**Continuous dependency updates:**
- Renovate (open-source) or Dependabot (GitHub-native) — daily PR cadence for non-major version bumps; weekly batched for major bumps.
- Auto-merge after CI passes for patch bumps; require human review for minor + major.

**Postgres major upgrade cadence:**
- Aim for staying within 2 major versions of current (i.e., currently 15 — upgrade to 16 sometime before 18 ships).
- Use logical replication for zero-downtime cutover at scale; pg_upgrade for self-hosted small instances.

### Current state

No documented cadence. Dependencies likely updated ad-hoc.
Postgres 15 is current; would need a plan to move to 16 before 18.

---

## 5. Capacity planning

### Why it matters

A SaaS without capacity planning hits a wall: traffic grows
imperceptibly week over week until a Monday morning when matching
takes 30 minutes per tenant instead of 30 seconds. By that point the
fix is multi-quarter.

### What we need

| Capability | Status | Phase |
|---|---|---|
| Per-tenant resource attribution | ⏳ A1 gap C1 | Phase 1 |
| Growth tracking (tenant count, inventory size, CVE count, request rate) | ⏳ Not started | Phase 1 |
| Headroom monitoring (current / max %) per shared resource | ⏳ Not started | Phase 1 |
| Scaling-trigger thresholds | ⏳ Not started | Phase 2 |
| Cost forecasting | ⏳ Not started | Phase 2 |
| Tenant cohort analysis (do Premium tenants cost more compute? by how much?) | ⏳ Not started | Phase 3 |

### Recommended approach

**Daily / weekly review:**
- A dashboard tracking: total tenants, total inventory rows, total CVE events, total `tenant_cve_matches`, total daily feed pulls, total daily inventory pushes.
- Each metric paired with its growth rate (week-over-week %).
- Each shared resource (Postgres CPU, Postgres connections, Redis memory, FastAPI request rate, S3 storage) paired with its current / max %.

**Trigger thresholds:**
- 70% headroom on any shared resource → ticket: investigate scaling.
- 85% → on-call paging.
- 95% → all-hands: scale immediately.

**Cost forecasting:**
- Per-tenant cost (from A1 gap C1, once shipped) × current tenant count × growth rate → 90-day forecast.
- Compare against revenue forecast → tier profitability.

### Current state

No capacity planning. The Portal will hit walls without warning until
the per-tenant attribution and growth dashboard exist.

---

## 6. Access control & operator management

### Why it matters

A multi-tenant SaaS has two sets of privileged actors:
1. **Operators** (Red Hat or partner engineers) — full admin via the operator API.
2. **Tenant administrators** (customer-side) — full admin within their tenant.

Both populations need provisioning, deprovisioning, audit, and review.

### What we need

| Capability | Status | Phase |
|---|---|---|
| Operator authentication via OIDC SSO (replaces single `PORTAL_ADMIN_TOKEN`) | ⏳ A1 gap S1 | Phase 1 |
| Per-operator audit log of admin actions | ⏳ Not started | Phase 1 (depends on OIDC) |
| Quarterly operator access review | ⏳ Not started | Phase 1 |
| Tenant-administrator provisioning workflow | ⏳ Not formalized | Phase 2 |
| Tenant-administrator audit log | ⏳ Partial — token usage tracked | Phase 2 |
| Emergency / break-glass access procedure | ⏳ Not started | Phase 2 |
| Production-access change-control (who has direct DB access, when) | ⏳ Not started | Phase 1 |

### Recommended approach

**OIDC operator SSO:**
- Integrate with the org's primary IdP (Red Hat SSO / Okta / Auth0).
- All admin API actions require OIDC.
- Per-operator JWT issued with scopes; `PORTAL_ADMIN_TOKEN` deprecated.
- Every admin write is logged: `ts, operator_id, action, target, before, after`.

**Quarterly access review:**
- Generate report from the audit log of operators with admin scopes who took at least one action in the quarter.
- Reviewed by engineering manager; access revoked for operators who have left the team.

**Production access:**
- Direct database access via bastion / `psql` is logged and time-bounded.
- Break-glass procedure: operator requests in Slack + manager approves in writing + access granted for 4 hours then auto-revoked.

### Current state

Single shared `PORTAL_ADMIN_TOKEN`; no audit log; no access review.
Won't pass a SOC 2 audit.

---

## 7. Configuration management

### Why it matters

The Portal's configuration spans: container images, environment
variables, Postgres schema, OPA bundles (for customer-facing
delivery), per-tenant settings, secrets. Drift between
environments (dev / staging / prod) and lack of source-of-truth
causes "it works on my machine" — and unrepeatable production
state.

### What we need

| Capability | Status | Phase |
|---|---|---|
| Infrastructure-as-code (Terraform / Pulumi / Crossplane) | ⏳ Not started | Phase 1 |
| Secrets management (Vault / KMS / sealed-secrets) | ⏳ Likely environment-variable today | Phase 1 |
| Environment promotion (dev → staging → prod) | ⏳ Not formalized | Phase 2 |
| Config drift detection | ⏳ Not started | Phase 2 |
| Schema migration tooling (alembic / migrate) | ⏳ Manual SQL files today | Phase 1 |
| Deployment pipeline (CI/CD) | ⏳ Likely manual today | Phase 1 |
| Feature flags | ⏳ Not started | Phase 2 |

### Recommended approach

**Phase 1:**
1. Terraform module for the Portal infrastructure (FastAPI service, Postgres, Redis, nginx). One module instance per environment.
2. Vault (HashiCorp Vault Enterprise — see `integrations/hashicorp_vault_enterprise/` write-up) for secrets. The Portal already integrates with Vault for customer compliance use cases; eating own dogfood here.
3. Alembic for Postgres schema migrations. Every migration committed to the repo; reviewed in PR; applied via CI in non-prod first.
4. GitHub Actions (or equivalent) for the deployment pipeline. Trigger on merge to `main`. Steps: build → test → push image → deploy to staging → manual approval → deploy to prod.

**Phase 2:**
5. Drift detection (Terraform plan in cron → alert on diff).
6. Feature flags via LaunchDarkly / Unleash / homegrown (`tenant_settings.feature_flags` JSONB). Gates new features per tenant; turns off without redeploy.

### Current state

Likely manual deployment + manual schema migrations. Acceptable for
the current pre-production state; not acceptable past first paying
customer.

---

## 8. Disaster recovery

### Why it matters

DR is the operational expression of A3's Surface 9 SLO (durability +
restore-success). The drill is when the SLO becomes a fact rather
than an aspiration.

### What we need

| Capability | Status | Phase |
|---|---|---|
| RPO / RTO targets defined per tier | ⏳ Recommended targets in A3 | Phase 1 |
| DR runbook (`docs/dr_runbook.md`) | ⏳ A1 gap R4 / brief Piece 31 | Phase 1 |
| First DR drill executed end-to-end | ⏳ Not started | Phase 1 |
| Quarterly DR drill cadence | ⏳ Not started | Phase 2 |
| Multi-region failover capability | ⏳ Brief Piece 34 | Phase 3 |
| Customer-facing DR communication template | ⏳ Not started | Phase 2 |

### Recommended approach

**Quarterly drill:**
- Stage a fresh environment from backups.
- Validate Postgres restore, OPA bundle availability, FastAPI service start, end-to-end customer feed pull.
- Measure empirical RPO and RTO; record vs targets.
- Capture lessons in the post-mortem; iterate the runbook.

**Multi-region failover (later):**
- Active-passive across two regions of the primary cloud.
- DNS-based switch-over with health checks.
- Quarterly failover drill (separate from the basic DR drill).

### Current state

No DR runbook, no drill. Recovery from a real loss-of-region event
would be reconstructive — uncertain duration, unknown data loss.
This is **the same risk as the backup gap** in §2 — same root cause,
same fix.

---

## 9. Security operations

### Why it matters

The Portal handles tenant authentication tokens, inventory
metadata, signed evidence bundles. A security incident in the
Portal directly compromises customers' compliance posture.

### What we need

| Capability | Status | Phase |
|---|---|---|
| Vulnerability scanning of Portal container images | ⏳ Not started | Phase 1 |
| SIEM / log forwarding (SOC integration) | ⏳ Not started | Phase 2 |
| Threat-detection rules against Portal logs (anomalous auth, mass deletes, etc.) | ⏳ Not started | Phase 2 |
| Penetration testing cadence (annual + on major change) | ⏳ Not started | Phase 2 |
| Bug bounty program | ⏳ Not started | Phase 3 |
| Security incident response (Sev 1 — overlaps with §3) | ⏳ Partial | Phase 1 |
| SBOM (Software Bill of Materials) for Portal | ⏳ Not started | Phase 1 |
| Customer security incident notification within 72 h | ⏳ Required for SOC 2; not yet | Phase 1 |

### Recommended approach

**Phase 1:**
1. Add Trivy / Grype scanning to the container build pipeline. Block merges on Critical / High CVEs.
2. Generate an SBOM (CycloneDX) per build; archive alongside the container image.
3. Defined security incident response — separate severity matrix variant where data-exposure is always Sev 1.

**Phase 2:**
4. Forward Portal application + infrastructure logs to a SIEM (Splunk / Elastic / Datadog Security).
5. Author 5–10 detection rules: anomalous admin actions, mass token revocations, rapid-fire 401s from a single source IP, sudden inventory-deletion spikes.
6. Schedule an annual pentest with a reputable firm.

**Phase 3:**
7. Bug bounty via HackerOne / Bugcrowd once mature enough to absorb the inbound report volume.

### Current state

No security operations beyond what the FastAPI defaults provide.
SOC 2 readiness has security operations as a major workstream.

---

## 10. Customer support operations

### Why it matters

The Portal sells a multi-tier service — Free customers get
community support, Premium customers get 4-hour P1 response. The
operational mechanics need to match.

### What we need

| Capability | Status | Phase |
|---|---|---|
| Tier-aware support routing | ⏳ Not formalized | Phase 1 |
| Ticketing system | ⏳ Not started | Phase 1 |
| Per-tier response-time SLOs | ⏳ Brief §6.4 informal targets | Phase 1 |
| Customer-impacting incident communication runbook | ⏳ Overlaps §3 | Phase 1 |
| Knowledge base + FAQ | ⏳ Not started | Phase 2 |
| Customer health scorecards | ⏳ Not started | Phase 3 |

### Recommended approach

**Tooling:** Zendesk / Intercom / Help Scout for ticketing; Discourse /
Slack Connect for the Free / community tier.

**Per-tier SLOs:**

| Tier | First response | Resolution target |
|---|---|---|
| Free | best-effort | n/a |
| Standard | 1 business day | 5 business days |
| Premium | 4 hours (P1), 1 business day (P2) | 1 day (P1), 3 days (P2) |
| Air-gapped | dedicated channel; bespoke |

**Customer-impacting incident communication:**
- Status page update first (§3).
- Affected-tenant email second (per their notification preferences).
- Premium tenants get a phone call from the engagement lead for Sev 1.

### Current state

Implicit — the engineering team currently does support directly via
Slack / email. Sustainable for the pre-production state; needs
formalization before the first paying customer.

---

## 11. Cost / FinOps

### Why it matters

A SaaS without per-tenant unit economics will either underprice
(unprofitable) or overprice (won't sell) tiers. The faster the
operations team can answer "how much does this tenant cost us per
month?" the faster the pricing model corrects itself.

### What we need

| Capability | Status | Phase |
|---|---|---|
| Cloud bill ingest (per-service, per-environment) | ⏳ Not started | Phase 1 |
| Per-tenant cost attribution | ⏳ A1 gap C1 | Phase 1 |
| Tier-cost rollup | ⏳ Not started | Phase 2 |
| Anomaly detection on bill | ⏳ Not started | Phase 2 |
| Reserved instance / spot strategy | ⏳ N/A until traffic pattern known | Phase 3 |

### Recommended approach

**Phase 1:**
1. Ingest the cloud bill (AWS Cost Explorer / Azure Cost Management / GCP Billing) into the same data plane (Postgres or a separate warehouse).
2. Per-tenant cost attribution (A1 C1) — tag DB queries + HTTP requests; aggregate hourly into `tenant_usage`.
3. Operator dashboard: cost per tenant per day; cost per tier; total infrastructure spend trend.

**Phase 2:**
4. Anomaly detection on bill — sudden increases in a service line item paged to operations.
5. Tier profitability dashboard fed into the pricing model conversation.

### Current state

No FinOps. Acceptable while pre-production; gates correct tier
pricing (decision D1 in the brief).

---

## 12. Change management — operational mechanics

### Why it matters

A3 defines *what* the change-management policy gates against (the
SLO error budget). This section defines *how* the gating actually
runs — who approves, who deploys, who rolls back.

### What we need

| Capability | Status | Phase |
|---|---|---|
| Documented release process | ⏳ Not started | Phase 1 |
| Change windows (regular + emergency) | ⏳ Overlaps §4 | Phase 1 |
| Deployment pipeline gates (CI passes + canary clean + approval) | ⏳ Not formalized | Phase 1 |
| Rollback procedure per deploy type | ⏳ Not started | Phase 1 |
| Customer notification for changes affecting their integration | ⏳ Not started | Phase 2 |
| API deprecation policy (versioning + sunset window) | ⏳ Partial (paths versioned) | Phase 2 |

### Recommended approach

**Standard release process:**

1. Engineer opens PR; CI runs unit + integration tests.
2. Code review by ≥ 1 peer.
3. Merge to `main` triggers staging deploy.
4. Smoke tests run against staging.
5. Canary deploy to 10% of Free-tier traffic; monitor SLO burn rates for 1 hour.
6. If clean, promote to 100%.
7. If burn-rate alert fires, auto-rollback.

**Emergency release (Sev 1 fix):**
- Skips canary if engineer + manager + on-call agree.
- Full smoke test still runs.
- Post-deploy monitoring tightened (15 min instead of 1 hr).
- Required post-mortem.

**API deprecation:**
- New major version published at `/api/portal/v2/`; old version remains.
- Customers given 6-month notice in changelog + status page + email.
- Customer's AAC bridges show a deprecation warning during the overlap window.

### Current state

Likely informal: engineer deploys when they think it's ready.
Sustainable while pre-production; not acceptable past first
paying customer.

---

## Maturity roadmap (phases)

A condensed view of when each capability needs to land.

### Phase 1 — day 0 to day 30 (pre-production / first internal use)

The minimum to **operate the Portal at all** without flying blind:

- §1 Monitoring — structured logging + per-tenant metrics + first Grafana boards
- §2 Backups — WAL streaming + daily backups + first test restore
- §3 On-call — severity matrix + on-call rotation + status page
- §4 Patch — monthly maintenance window + Renovate / Dependabot
- §5 Capacity — growth dashboard
- §6 Access — OIDC operator SSO + admin audit log
- §7 Config — IaC + secrets in Vault + Alembic + CI/CD
- §9 Security — image scanning + SBOM
- §12 Change management — documented release process

### Phase 2 — day 30 to day 90 (first external customer)

Add reliability, security depth, and customer-facing operational
contract:

- §1 Tracing + burn-rate alerts + synthetic monitoring
- §2 Selective-tenant restore + documented RPO/RTO
- §3 Game day + tabletop
- §4 Postgres major upgrade cadence
- §5 Scaling-trigger thresholds + cost forecasting
- §6 Quarterly access review + break-glass procedure
- §7 Drift detection + feature flags
- §8 DR runbook + first quarterly drill
- §9 SIEM + detection rules + annual pentest
- §10 Tier-aware support routing + ticketing system
- §11 Per-tenant cost attribution dashboard
- §12 Customer notification + API deprecation policy

### Phase 3 — day 90 to day 365 (scale + SOC 2 readiness)

- §1 RUM + anomaly detection
- §2 Cross-region backups
- §5 Tenant cohort analysis
- §8 Multi-region failover
- §9 Bug bounty
- §10 Customer health scorecards
- §11 Reserved-instance strategy

---

## Open questions

| # | Question | Decision owner |
|---|---|---|
| Q1 | Open-source observability stack (Prometheus/Grafana/Loki/OTel) or hosted SaaS (Datadog)? | Engineering |
| Q2 | Self-hosted Postgres or managed (RDS / Cloud SQL)? Affects backup approach. | Engineering / leadership |
| Q3 | PagerDuty (industry-standard) or self-host paging (Grafana OnCall) to start? | Operations |
| Q4 | Which IdP for operator OIDC SSO? Internal Red Hat SSO or Okta? | Security / IT |
| Q5 | Ticketing system — Zendesk / Intercom / Help Scout / self-host? | Customer success |
| Q6 | When does first DR drill happen — before or after first external customer? | Leadership |
| Q7 | SOC 2 readiness budget + timeline — Drata, Vanta, or a consultancy? | Leadership |

---

**Authored with Claude (Anthropic).**
