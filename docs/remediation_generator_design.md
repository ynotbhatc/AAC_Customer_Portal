# AAC Customer Portal — Remediation Generator Design

**Audience:** Internal planning — engineering, product, security review.
**Purpose:** Design specification for the **Backup → Patch → Validate**
remediation generator (brief Piece 21 + TaskCreate #47). Companion to
`policy_ingestion_design.md` (Phase 5 of the compliance loop). Defines
the contract, the per-vendor role library, the IR-to-playbook generator,
the customer review flow, and the AAC integration.
**Drafted:** 2026-06-02
**Version:** v1.0

## Revision history

| Version | Date | Change |
|---|---|---|
| v1.0 | 2026-06-02 | Initial design. Backup → Patch → Validate contract spec. Per-vendor role library structure. IR-to-remediation generator. Customer review + approval workflow. AAC AAP integration. Failure-mode and rollback semantics. Frames the priority as **measurable first** — administrative governance overlays defer. |

---

## 0. Guiding principle — measurable first

> **The first things we automate are the things we can objectively
> measure.** Technology states — file permissions, service configs,
> password policy settings, audit log enablement, encryption flags,
> open ports, registry values, network device running-configs — are
> binary, observable, and comparable. They produce evidence with no
> human judgment in the middle.
>
> Administrative controls — training completeness, incident response
> procedures, vendor risk assessments, BCP testing — require process
> attestations rather than measurement. They matter, but they belong
> later in the roadmap.

This principle drives the priority ordering throughout this document:

- The **Validate step (§2)** re-runs the same Rego that found the gap.
  The post-condition is measurable — the same OPA evaluation that
  produced the gap produces the proof of remediation.
- The **per-vendor role library (§3)** covers technology-state
  controls only. No process attestations in the role catalog.
- The **starter library scope (§12)** is sized to measurable controls
  the largest enterprise customers actually run: password policy,
  audit logging, sshd hardening, account lockout, network logging,
  service hardening, patch currency. Each one is a config inspection.
- The **audit trail (§7, §11)** emphasizes what we can prove
  objectively: backup taken (artifact + SHA), patch applied (Ansible
  exit + diff), validate passed (Rego compliance result), rollback
  succeeded (re-evaluation result). Every link in the chain is
  observable.

The administrative governance work in `policy_ingestion_design.md`
§23 (control ownership, periodic review, exception management, risk
linkage) is **deferred to after the measurable layer ships**. We get
the technical loop running first; governance overlays follow.

---

## 1. Where this sits in the compliance loop

```
   policy_ingestion → Rego  ─────────────┐
                                          │
                                          ▼
   AAC assessment finds gap ────► [tenant_cve_matches | compliance_results gaps]
                                          │
                                          ▼
   ──► remediation_generator (THIS DOC)
       ├─ pull IR + assessment context
       ├─ map to (abstract_control × target_system) → remediation template
       ├─ generate Backup → Patch → Validate playbook
       ├─ customer reviews + approves
       └─ AAP launches the workflow
                                          │
                                          ▼
   AAC re-assessment → confirms compliance restored
                                          │
                                          ▼
   audit log + audit-ready report (Phase 7)
```

The remediation generator is the **action layer** of the compliance
loop. The same IR that produced the Rego check now produces the
Ansible role that closes the gap.

This means **one customer policy upload feeds two derivative
artifacts** — Rego (validates state) + remediation playbook (changes
state). They share an IR and stay in lockstep when the policy
changes.

---

## 2. The Backup → Patch → Validate contract

Every Portal-generated remediation workflow follows the same
three-step shape:

```
┌──────────────────────────────────────────────────────────────┐
│ STEP 1 — BACKUP                                              │
│   Save the system's current state for the affected component │
│   so the change can be reversed if Validate fails.           │
│                                                              │
│   Examples:                                                  │
│     - Linux config:    cp /etc/login.defs /var/backup/...    │
│     - Windows GP:      Backup-GPO -Name "Default Domain..."  │
│     - Cisco IOS:       'copy running-config flash:pre-X.cfg' │
│     - z/OS:            Save RACF SETROPTS LIST output        │
│     - VM:              snapshot via cloud / hypervisor API   │
│     - K8s:             kubectl get -o yaml | save             │
└─────────────────┬────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 2 — PATCH                                               │
│   Apply the change that closes the gap. Vendor-specific      │
│   Ansible role drawn from the per-vendor library (§5).       │
│                                                              │
│   Examples:                                                  │
│     - Linux:           lineinfile / template / pam_module    │
│     - Windows:         win_secedit / win_lineinfile / GPO    │
│     - Cisco IOS:       ios_config + commit/save              │
│     - z/OS:            zos_operator commands via z/OSMF      │
└─────────────────┬────────────────────────────────────────────┘
                  │
                  ▼
┌──────────────────────────────────────────────────────────────┐
│ STEP 3 — VALIDATE                                            │
│   Re-collect facts from the affected component.              │
│   Re-evaluate the same Rego policy against the new facts.    │
│   PASS → record success; FAIL → invoke ROLLBACK using STEP 1 │
│   backup; either way, log the outcome with provenance.       │
└──────────────────────────────────────────────────────────────┘
```

### Why this shape is non-negotiable

| Property | Why it matters |
|---|---|
| **Backup before any change** | Every customer's first question: "what if it breaks?" The backup is the answer. Always exists; always testable. |
| **Vendor-agnostic step contract** | Same three-step skeleton across RHEL, Windows, Cisco, z/OS, AWS, K8s. Only the verbs inside each step are vendor-specific. Lets the Portal generate a workflow without knowing vendor-specific failure modes. |
| **Patch is the only step that mutates state** | Backup and Validate are read-only on the target. Reduces risk of cascading damage if a step fails mid-flight. |
| **Validate runs the same Rego that found the gap** | No drift between "what we said the policy is" and "what we just checked." The post-condition is *provably* what the customer asked for. |
| **Rollback uses the backup** | When Validate fails, the workflow restores from Step 1's artifact, then re-validates. If rollback succeeds, system is back to pre-Patch state. If rollback fails, page operator — but pre-Patch state was captured, so recovery is possible. |

### What the contract does NOT prescribe

Intentional flexibility:

- **Approval gate between Backup and Patch** is optional per tenant tier / per policy. Premium customers may require Account Owner approval; Standard tier may auto-proceed. Implemented as an optional workflow node, not a structural requirement.
- **Per-host vs bulk execution** — workflow accepts a `hosts` parameter; runs the same three steps per-host or batched, customer choice.
- **Parallelism cap** — workflow accepts a `serial` parameter (Ansible's `serial` keyword). Default 1 (one host at a time, safest); tunable per customer.
- **Notification recipient** — pluggable. Customer's BigPanda incident, Slack channel, email distribution list, ServiceNow ticket — all valid endpoints.

---

## 3. Per-vendor role library

The Patch step (§2 step 2) is implemented as a vendor-specific Ansible
role. The library is the **target_mappings.remediation_template** column
from the policy ingestion data model — but the engine type is fixed at
`ansible_role`.

### Vendor families covered in the starter library

| Vendor family | Coverage | Notes |
|---|---|---|
| **Linux: RHEL 8/9/10, CentOS, Rocky, Amazon Linux 2023** | full | Most controls express as file edits + service reloads |
| **Linux: Ubuntu 20.04/22.04/24.04, Debian** | full | Diverges from RHEL in package manager + service framework but Ansible abstracts most of it |
| **Linux: SUSE / SLES** | partial | Less common; templates added on customer demand |
| **Windows: Server 2019/2022, Windows 10/11** | full | Secedit / GPO / registry / WMI primitives |
| **Network: Cisco IOS-XE / NX-OS** | full | `cisco.ios` / `cisco.nxos` collections |
| **Network: Juniper Junos** | full | `junipernetworks.junos` collection |
| **Network: Palo Alto** | partial | `paloaltonetworks.panos` |
| **Network: Fortinet, Arista** | partial | community collections; certified-collection availability varies |
| **Mainframe: IBM z/OS RACF + ACF2 + Top Secret** | partial | `ibm.ibm_zos_core` collection; some controls require zOSMF setup |
| **Hypervisor: VMware vSphere** | partial | `vmware.vmware_rest` |
| **Cloud: AWS / Azure / GCP** | partial | `amazon.aws`, `azure.azcollection`, `google.cloud` |
| **Container: Docker / Kubernetes** | full | `kubernetes.core` + `community.docker` |
| **Identity: Active Directory, FreeIPA** | partial | `microsoft.ad`, `freeipa.ansible_freeipa` |

### Role structure on disk

Each role lives at:

```
portal/remediation/library/
└── <vendor_family>/
    └── <abstract_control_key>/
        ├── tasks/
        │   ├── backup.yml          ← STEP 1 implementation
        │   ├── patch.yml           ← STEP 2 implementation
        │   ├── validate.yml        ← STEP 3 implementation (re-runs the Rego)
        │   └── rollback.yml        ← STEP 3-fail recovery
        ├── handlers/main.yml       ← service reloads, daemons etc.
        ├── defaults/main.yml       ← parameter defaults from the IR
        ├── meta/main.yml           ← Ansible role metadata
        └── README.md               ← human-readable: what this role does, prereqs, limitations
```

Example tree for `linux_rhel × password_complexity`:

```
portal/remediation/library/linux_rhel/password_complexity/
├── tasks/
│   ├── backup.yml          ← cp /etc/login.defs + /etc/security/pwquality.conf to /var/backup
│   ├── patch.yml           ← lineinfile updates for min length, complexity rules; pwquality.conf overwrite
│   ├── validate.yml        ← re-run cis_rhel9.pam_validation Rego against fresh facts
│   └── rollback.yml        ← restore from /var/backup if validate failed
├── handlers/main.yml       ← restart sshd if PAM-affected
├── defaults/main.yml       ← min_length: 12  require_upper: true  require_digit: true  …
├── meta/main.yml
└── README.md
```

### IR-to-defaults mapping

The customer policy IR (from `policy_ingestion_design.md` §10) carries
parameter values. These are injected into the role's defaults at
generation time:

```yaml
# customer's IR
control_intents:
  - abstract_control_key: password_complexity
    parameters:
      min_length: 12
      require_upper: true
      require_lower: true
      require_digit: true
      require_symbol: true
      max_age_days: 90
```

```yaml
# generated defaults/main.yml (per-customer overlay of role)
---
# Auto-generated by Portal remediation generator
# Source: customer_policy_id=<uuid> version=v1.2 ir_sha=<sha>
password_complexity_min_length: 12
password_complexity_require_upper: true
password_complexity_require_lower: true
password_complexity_require_digit: true
password_complexity_require_symbol: true
password_complexity_max_age_days: 90
```

The role's task files reference these variables — they don't change
per customer; only the defaults do. **One role, N customer-specific
parameter overlays.**

---

## 4. The generator

For each (abstract_control × target_system) pair appearing in the
customer's IR + inventory:

```python
def generate_remediation(customer_policy, target_system, ir_parameters):
    template = lookup_remediation_template(
        customer_policy.ir_json.control_intents[*].abstract_control_key,
        target_system
    )

    if template and template.engine == 'ansible_role':
        # Hot path — library covers this combination
        playbook = render_playbook_from_role(
            role=template.role_path,
            parameters=ir_parameters,
            backup_step=template.backup_step,
            validate_step=template.validate_step,
            rollback_step=template.rollback_step,
        )
        confidence = template.quality_grade  # library_v1 → 0.95
        method = 'role_based'

    elif template and template.engine == 'llm_prompt':
        # Skeleton + LLM fills in vendor-specific tasks
        playbook = llm_generate_playbook(template.body, ir_parameters)
        confidence = 0.75
        method = 'llm_with_skeleton'

    else:
        # Pure LLM — no library coverage for this combination
        playbook = llm_generate_playbook(
            generic_remediation_prompt(abstract_control_key, target_system),
            ir_parameters,
        )
        confidence = 0.55
        method = 'llm_fallback'

    playbook = inject_three_step_skeleton(playbook)  # ensure Backup/Patch/Validate structure
    validate_playbook(playbook)  # ansible-lint + dry-run
    return playbook, confidence, method
```

Every generated playbook carries provenance fields in its header
comment — `generation_method`, `confidence_score`, IR sha, customer
policy version, role version. The audit-ready report (Phase 7)
includes these.

### Hybrid + LLM-fallback (the §2 principle applied)

Same hybrid approach as policy ingestion. Library-backed where it
exists; LLM-with-skeleton when partial; pure LLM when nothing else.
**Confidence + generation_method tagged on every artifact** so the
customer review UI can flag low-confidence cases for extra scrutiny.

---

## 5. Customer review + approval workflow

The customer never runs Portal-generated remediation without seeing it
first. The flow:

```
1. AAC assessment lands gap rows in compliance_results
2. Portal cron correlates gaps × customer policies → identifies remediation candidates
3. Portal generates Backup → Patch → Validate playbook per (policy × target_system × host group)
4. Notification sent to control_owner_user_id + optional Account Owner CC:
   "12 hosts failing your Acme Password Policy. Review remediation?"
5. Owner opens the review UI:
   - Side-by-side diff vs library role (if overlay applied)
   - Per-step preview (Backup commands, Patch tasks, Validate query)
   - Host list with current vs target values
   - Confidence score + generation method flag
6. Owner can:
   (a) Approve → AAP launches the workflow
   (b) Edit → save as customer-modified version, re-validate, re-submit
   (c) Reject + reason → record audit trail; no workflow runs
7. AAP runs Backup → Patch → Validate per host (or per batch, per tenant policy)
8. Outcomes recorded:
   - Per-host success/failure
   - Backup artifact location (S3 key)
   - Time elapsed
   - Validate result (Rego compliance %)
9. Notification on completion. If any host failed Validate + rollback succeeded
   → "rolled back automatically, escalation required"
   If rollback also failed → SEV-2 page to operator
10. Audit log captures every action with actor, MFA-asserted identity, timestamp
```

### Per-tier review gates

| Tier | Default gate |
|---|---|
| Free | Auto-approve after 24-hour preview window (with email opt-out) — for low-risk policies only |
| Standard | Owner must approve manually; default per-host serial execution |
| Premium | Owner + change-management webhook (ServiceNow CR) required; bulk execution OK with approval |
| Air-gapped | Bundle export; customer's internal change-management runs the workflow on their AAP |

The gates are **policy-engine driven** (same as RBAC — §2 principle).
Adding finer-grained gates ("Owner + Security approval for any policy
affecting SOX-scoped systems") is a policy rule, not a code change.

---

## 6. AAC integration

### AAP job templates

The remediation workflow is implemented as **one parameterized AAP
workflow template** per tenant, instantiated once at tenant
onboarding by the `aac-portal-bridge` role:

```
AAC - Customer Remediation: Backup → Patch → Validate
  Survey:
    customer_policy_id        (uuid)
    target_system             (string)
    affected_hosts            (list[string])
    serial                    (int, default 1)
    notify_on_completion      (list[string])  # webhooks / emails
    require_approval          (bool, default per-tier)
  Workflow nodes:
    [1] Pull generated playbook from Portal (signed)
    [2] Verify signature
    [3] Optional approval gate (workflow approval node)
    [4] Run Backup step against affected_hosts
    [5] Run Patch step against affected_hosts (parallelism = serial)
    [6] Run Validate step
    [7] On Validate failure → Run Rollback step → re-Validate
    [8] Emit Portal callback with outcomes
    [9] On rollback failure → notify operator (Portal-side SEV-2)
```

The customer's AAC bridge launches this template. Inputs come from the
Portal's gap-detection event. Outputs (per-host outcomes + signed
audit envelope) flow back through the existing `aac_portal_feed`
channel.

### Why one parameterized template, not N templates per (policy × target)

If we instantiated N templates per tenant, every new customer policy
would require a template create. Bridge fleet of 100 customers ×
100 policies × 5 targets = 50,000 templates to manage. One
parameterized template with a survey scales linearly with tenants,
not with policy combinations.

The cost: per-launch we pass the playbook content via signed S3 key
(survey field) — slightly more complex than embedding it, but vastly
simpler operationally.

### Backup step targets per vendor

| Target family | Backup mechanism |
|---|---|
| Linux config-file controls | `copy src=<file> dest=/var/backup/portal/<run_id>/` |
| Linux service controls | `systemctl status <svc>` snapshot + `systemctl cat <svc>` to backup |
| Windows GPO controls | `Backup-GPO -Name <gpo> -Path <S3-keyed-share>` |
| Windows registry controls | `Export-Registry` to backup share |
| Cisco IOS controls | `copy running-config flash:<backup-name>` + Portal pulls config diff |
| z/OS RACF controls | `SETROPTS LIST` + `LISTUSER` snapshots saved to dataset |
| VM-level controls | Cloud snapshot API call (AWS `CreateSnapshot`, Azure `Snapshot.create`, etc.) |
| Container controls | `kubectl get -o yaml <resource>` saved to backup |

**Backup artifact storage:** customer's choice — Portal-hosted S3-compatible bucket per tenant (default) OR customer's own S3-compatible target (specified at tenant onboarding). Backups are retained per the tenant's `backup_retention_days` setting; signed with the Portal's authoritative key for tamper-evidence.

### Validate step — re-run the same Rego

The validate step is just "run the same Rego that found the gap,
against fresh facts gathered after Patch":

```yaml
- name: Re-gather facts for compliance re-evaluation
  ansible.builtin.setup:

- name: Run customer-specific Rego policy against fresh facts
  ansible.builtin.uri:
    url: "{{ opa_url }}/v1/data/{{ rego_package }}/compliance_report"
    method: POST
    body_format: json
    body:
      input: "{{ ansible_facts }}"
    return_content: yes
  register: validate_result

- name: Fail if compliance not restored
  ansible.builtin.fail:
    msg: "Validate failed: {{ validate_result.json.result.violations }}"
  when: not validate_result.json.result.compliant
```

No new Rego is generated for validation — the same policy is the
truth. If the Rego is wrong, the Validate step legitimately fails,
and the customer is alerted to a Rego bug, not a target-system
problem.

---

## 7. Failure modes and rollback semantics

| Failure | Detection | Response |
|---|---|---|
| **Backup step fails** | Ansible exit non-zero on step 1 | Abort workflow. No state mutated. Notify owner with reason. |
| **Patch step fails (single host)** | Ansible exit non-zero on a single host | Continue with other hosts if `serial` > 1 and `any_errors_fatal: false`. Record per-host failure. |
| **Patch step fails (all hosts in serial=1 batch)** | First Patch fails | Abort workflow. Run Rollback for the host that did get patched (if any). Audit log captures attempt. |
| **Validate step fails (compliance not restored)** | Rego returns `compliant: false` | Run Rollback step. Re-run Validate. If now-passing (because rollback restored pre-Patch state), mark "rolled back, retry not auto-attempted." |
| **Rollback step fails** | Ansible exit non-zero on rollback | SEV-2 page to Portal operator. Host left in indeterminate state (Backup exists but Restore didn't apply). Operator + customer engage. |
| **OPA unavailable for Validate** | HTTP failure | Retry with backoff (3 attempts, exponential). If still failing, treat as Validate failure → trigger Rollback. |
| **Mid-workflow Portal outage** | AAP can't fetch playbook | Workflow pauses at node 1 (signed-fetch). Resumes when Portal returns. Bounded retries. |
| **MFA challenge timeout during approval** | Approval node expires after configurable window (default 4 hours) | Workflow auto-rejects. Customer can re-request remediation. |

Every failure mode lands a `policy_audit_log` entry with the AAP
job ID, per-host outcomes, and the human-actionable next step. Phase
7 audit reports include this — auditors LOVE seeing "remediation
attempted, validate failed, rollback succeeded, escalation
documented."

---

## 8. Data model additions

Extending the policy ingestion design (§7):

### `customer_remediation_runs`

Each invocation of the workflow — one row per (gap detection event ×
remediation attempt).

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | FK |
| `customer_policy_id` | uuid | FK |
| `target_system` | text | matches policy_targets |
| `assessment_compliance_results_id` | uuid | FK → compliance_results row that triggered |
| `aap_workflow_job_id` | int | The launched workflow job; reconstructable for audit |
| `playbook_storage_key` | text | S3 key to the signed playbook |
| `playbook_sha256` | text | Integrity check |
| `generation_method` | enum | `role_based`, `llm_with_skeleton`, `llm_fallback` |
| `confidence_score` | float | 0.0-1.0 from generator |
| `approved_by_user_id` | uuid | nullable until approved |
| `approved_at` | timestamptz | |
| `requested_at` | timestamptz | |
| `started_at` | timestamptz | nullable |
| `finished_at` | timestamptz | nullable |
| `outcome` | enum | `pending`, `approved`, `running`, `succeeded`, `partial`, `failed_patch`, `failed_validate_rolled_back`, `failed_validate_rollback_failed`, `rejected_by_owner`, `expired` |
| `affected_hosts` | jsonb | per-host outcomes |
| `backup_artifact_keys` | jsonb | per-host backup storage references |

### Extension to `target_mappings`

Adds three columns (already mentioned in policy ingestion design §6
as forward-compatible):

| Column | Notes |
|---|---|
| `remediation_engine` | `ansible_role`, `llm_prompt`, `none` |
| `remediation_role_path` | If `ansible_role`: relative path to the role on disk |
| `remediation_quality_grade` | `library_v1`, `experimental`, `community`, `deprecated` |

---

## 9. API surface (new endpoints)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/portal/v1/tenants/{tenant_id}/remediations` | List remediations (pending + history) |
| GET | `/api/portal/v1/tenants/{tenant_id}/remediations/{id}` | Detail view with playbook content, host list, status |
| GET | `/api/portal/v1/tenants/{tenant_id}/remediations/{id}/playbook` | Get signed playbook (for the bridge) |
| POST | `/api/portal/v1/tenants/{tenant_id}/remediations/{id}/approve` | Owner approves — workflow launches |
| POST | `/api/portal/v1/tenants/{tenant_id}/remediations/{id}/reject` | Owner rejects (with reason) |
| PATCH | `/api/portal/v1/tenants/{tenant_id}/remediations/{id}/playbook` | Owner edits before approving (low-confidence cases) |
| POST | `/api/portal/v1/tenants/{tenant_id}/remediations/{id}/outcomes` | AAC callback — per-host outcomes after run |
| GET | `/api/portal/v1/tenants/{tenant_id}/remediations/{id}/backup-artifacts` | Pre-signed URLs for backup retrieval (audit / DR use) |

All write endpoints gated by RBAC + MFA + per-tenant policy engine
per the §2 principle in policy ingestion.

---

## 10. Frontend pages

| Route | Purpose |
|---|---|
| `/remediations` | Dashboard — open remediations + recent outcomes; counts per state |
| `/remediations/{id}/review` | Review UI — Backup/Patch/Validate preview side-by-side, host list, confidence flag, approve/edit/reject actions |
| `/remediations/{id}/outcome` | Outcome view — per-host status, backup links, validate results, rollback evidence (if applicable) |
| `/remediations/library` | Browse the per-vendor role library — read-only documentation |
| `/remediations/audit` | Filterable audit log of remediations (per-tenant) |

---

## 11. Open questions (tweak as we go)

| # | Question | Default for MVP |
|---|---|---|
| 1 | Should Portal-side cron always generate playbooks for every gap, or only on customer demand? | **On every assessment with compliance drop ≥ 5%** — bulk-generate at the same cadence as assessment |
| 2 | Approval gate default per tier — proposed in §5; revisit if customers push back | As proposed |
| 3 | Backup artifact retention default | **90 days; longer per tier** |
| 4 | Should we expose the LLM-fallback prompts to the customer? | **Yes** — full transparency on what we asked the LLM to generate |
| 5 | Library role versioning — should we semver per role or per release? | **Per role** — finer-grained drift detection |
| 6 | Customer wants to add a custom step (e.g., "Notify SOC before Patch") | **Plugin model** — pluggable workflow nodes between standard steps |
| 7 | Rollback for irreversible changes (e.g., disk reformat, password reset) | **Out of scope** — Portal warns "this remediation has no reversible backup; require explicit waiver" |
| 8 | Cross-host atomicity (all hosts succeed or all roll back) | **Per-host MVP**; cross-host atomic mode later |
| 9 | Should remediation generation block on a successful drift-detection diff? | **Yes** — if customer overlay differs from generator template, surface the diff for owner review |
| 10 | Backup encryption at rest | **Required from MVP** — signed with Portal authoritative key + per-tenant customer-managed key for envelope encryption (KMS-style) |

---

## 12. Phased implementation plan

This is **Phase 5** of the policy ingestion design's phased plan
(§22 there). Two sprints. Builds on Phase 1-4 of policy ingestion
having shipped.

### Sprint 9 — generator + AAP plumbing

1. New tables: `customer_remediation_runs`, extensions to `target_mappings`
2. Starter role library — 10 abstract controls × 4 vendor families = 40 roles, all carrying the three-step contract
3. Generator service (`api/src/policy_ingestion/remediation_generator.py`) — same hybrid engine as Rego generation
4. Playbook validation (`ansible-lint` + Ansible dry-run against a sandbox host)
5. AAP workflow template definition (`AAC - Customer Remediation: Backup → Patch → Validate`) seeded into the customer's AAC by the bridge role
6. Signed-playbook fetch endpoint (`GET /remediations/{id}/playbook`)

### Sprint 10 — review UI + outcomes + audit

7. Frontend `/remediations` dashboard
8. Review UI with side-by-side diff + host list + confidence flagging
9. Approve/reject endpoints with MFA challenge for write actions
10. AAP callback ingestion (`POST /remediations/{id}/outcomes`)
11. Audit log integration
12. End-to-end soak test against a sandbox customer tenant (RHEL + Windows + Cisco IOS targets)

---

## 13. References

### Builds on / depends on

- `policy_ingestion_design.md` — sibling design; IR + target_mappings come from there
- `portal_capabilities_brief.md` §6.3 (Compliance-as-a-service) + Piece 21 (Backup → Patch → Validate workflow contract)
- AAC task #45 (OPA bundle mode) — Validate step uses the loaded bundle
- Phase 4 of the policy ingestion plan must ship before Phase 5 starts

### Standards + practice

- Ansible best practices for idempotent remediation
- OWASP A05 (Security Misconfiguration) — the class of issues this most often addresses
- ITIL change management — the approval gate concept

---

**Authored with Claude (Anthropic).**
