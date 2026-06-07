# AAC Customer Portal — Golden Image Generator Design

**Audience:** Internal planning — engineering, product, security review, customer DevOps lead reviews.
**Purpose:** Design specification for **Phase 6** of the compliance loop — the golden image generator. Companion to `policy_ingestion_design.md` (Phase 1-4) and `remediation_generator_design.md` (Phase 5). Defines per-target image template library, the IR-to-provisioning-artifact generator, the build-attestation contract, the rebuild-on-policy-update lifecycle, and the customer CI/CD integration.
**Drafted:** 2026-06-02
**Version:** v1.0

## Revision history

| Version | Date | Change |
|---|---|---|
| v1.0 | 2026-06-02 | Initial design. Per-target image template library (Kickstart / cloud-init / Packer / Containerfile / unattend.xml / network device startup-config). Hybrid template + LLM generator (same engine as Phases 1-5). SLSA Level 3 attestation contract for build provenance. Image lifecycle tracking with rebuild-suggested-on-policy-change. AAC integration via customer CI/CD pipeline patterns. Failure modes + signing model + air-gap accommodations. |

---

## 0. Guiding principle — measurable first (continuing from Phase 5)

> **The first things we automate are the things we can objectively
> measure.** Golden image generation is squarely in the measurable
> camp: image config is auditable (parameters in defaults map to IR);
> build is reproducible (pinned base + pinned versions); resulting
> image can be assessed by AAC (same Rego, fresh facts on the new
> system); "was this image built from policy version X?" is a
> yes/no question with a cryptographic answer.

Three measurable claims this design enables a customer to prove:

1. **"This image was built from a specific policy version."** — verifiable via build-time attestation signed with the Portal's authoritative key.
2. **"This running system was provisioned from a specific image."** — verifiable via the image SHA in cloud metadata + Ansible facts at first-boot.
3. **"This running system, freshly provisioned, passes the policy it was built against."** — verifiable by AAC assessment running immediately post-provision against the SAME Rego the image was generated from.

The third one is the closed loop: **born compliant, immediately
verifiable.** That's the value prop golden image work unlocks.

Administrative governance overlays (control owner, policy review,
attestation review processes) remain deferred to Phase 8 per the §2.1
sub-principle in policy ingestion design v1.3.

---

## 1. Where this sits in the compliance loop

```
   policy_ingestion → IR  ──────────────┐
                                         │
       ┌─────────────────────────────────┤
       │                                 │
       ▼                                 ▼
   Rego validator                  Remediation gen
   (Phase 1-4)                     (Phase 5)
       │                                 │
       │                                 │
       │                                 │
       │                                 │
       │                       ┌─────────┴─────────┐
       │                       ▼                   ▼
       │              ┌────────────────┐  ┌────────────────┐
       │              │ AAC remediates │  │ Golden image   │
       │              │ existing infra │  │ generator      │
       │              └────────────────┘  │ (THIS DOC)     │
       │                                  └────────┬───────┘
       │                                           │
       │                                           ▼
       │                                  Customer CI/CD
       │                                  builds & signs
       │                                  the new image
       │                                           │
       │                                           ▼
       │                                  Image deployed →
       │                                  immediately
       │                                  passes assessment
       │                                  against same Rego
       └──────────────────────────────────────────┘
                                                   │
                                                   ▼
                                  audit-ready report (Phase 7)
                                  cites the image attestation
                                  as evidence that "born
                                  compliant" was achieved.
```

**The closed-loop value:**

Without golden images, the compliance lifecycle is
*deploy → assess → find gaps → remediate → re-assess*. Every new
system spends its first minutes-to-hours in non-compliant state.

With golden images, the lifecycle becomes *generate-from-policy →
build-once → deploy → assess → done*. New systems are compliant
**before they touch production traffic**, and any drift after that
point is a known event (someone changed something) rather than an
expected starting condition.

For customers under regulatory scrutiny (PCI, HIPAA, FedRAMP), the
"born compliant" property is often the only acceptable answer.

---

## 2. The contract — "born compliant"

Every Portal-generated golden image satisfies three properties:

### 2.1 Policy-aligned configuration

The image's installed configuration matches every measurable control
intent in the IR — passwords, audit logging, SSH hardening, service
state, encryption flags, network rules, etc. The image **doesn't need
remediation immediately after boot** because the configuration is
correct at boot.

### 2.2 Reproducible build

Given the same IR + same base image SHA + same image-format template
SHA, the build produces a bit-identical (or content-identical, per
the format's idempotency semantics) image. Reproducibility is a
SLSA Level 3+ property; we target it from MVP.

### 2.3 Verifiable provenance

Every image carries a **build attestation** signed by the Portal's
authoritative key:

```json
{
  "image_sha256": "sha256:...",
  "policy_version_set": [
    {"customer_policy_id": "...", "version_semver": "v1.2"},
    {"customer_policy_id": "...", "version_semver": "v3.0"}
  ],
  "portal_template_sha": "sha256:...",
  "base_image_sha": "sha256:...",
  "build_started_at": "...",
  "build_finished_at": "...",
  "builder_identity": "...",
  "attestation_format": "in-toto/SLSA-1.0",
  "portal_signature": "..."
}
```

The customer's CI/CD posts this attestation back to the Portal at
the end of every successful image build. Auditors can verify any
deployed system's chain of custody from running instance →
attestation → policy version it was built against.

### 2.4 What the contract does NOT require

Intentional flexibility:

- **Base image choice** — customer picks (RHEL UBI, official Ubuntu, Amazon Linux, Microsoft Windows ISO, etc.). Portal generator works with any compliant base; doesn't require a Portal-curated base image.
- **CI/CD platform** — customer's choice (GitHub Actions, GitLab CI, Tekton, Jenkins, Azure Pipelines, AWS CodeBuild). Generator produces standard format artifacts; customer's CI plumbing executes them.
- **Image registry** — customer's choice for where signed images land (ECR, ACR, GCR, Quay, Harbor, self-hosted Docker Distribution).
- **Build cadence** — customer's choice. MVP supports: on-demand, on-policy-publish (webhook), on-schedule.

---

## 3. Per-target image template library

The library is structured similarly to the remediation library
(`remediation_generator_design.md` §3): per-vendor-family directories
holding the templates for each `(abstract_control × image_format)`
combination.

### 3.1 Image format coverage

| Image format | Used for | MVP starter coverage |
|---|---|---|
| **Kickstart `.ks`** | Bare-metal + PXE-booted RHEL/CentOS/Rocky/Amazon Linux installs | ✅ MVP |
| **cloud-init YAML** | Ubuntu autoinstall + cloud-image first-boot | ✅ MVP |
| **Packer manifest + provisioner playbook** | AWS AMI, Azure Image, GCP image — across both Linux and Windows | ✅ MVP |
| **Containerfile / Dockerfile** | OCI container base images | ✅ MVP |
| **unattend.xml + sysprep** | Windows Server / Windows 10/11 first-boot | ✅ MVP |
| **Group Policy XML bundles** | Windows AD-joined images | ✅ MVP |
| **vCenter VM template `.ovf` + customization spec** | VMware-managed VMs | 🟡 Phase 6.5 |
| **Network device startup-config** | Cisco IOS / Juniper Junos / Arista EOS — declarative startup config baked at provisioning | 🟡 Phase 6.5 |
| **Kubernetes manifests** (PodSecurityPolicy → OPA Gatekeeper constraints) | K8s admission control aligned to policy | ⏳ Phase 6.5 |
| **Packer for mainframe (z/OS) installation profiles** | RACF / ACF2 baseline | ⏳ post-MVP |

### 3.2 Library directory structure

```
portal/golden-image/library/
└── <vendor_family>/
    └── <abstract_control_key>/
        └── <image_format>/
            ├── template.j2          ← Jinja2 template producing the artifact
            ├── defaults.yaml        ← parameter defaults consumed from IR
            ├── verify.sh            ← post-build verification harness
            ├── meta.yaml            ← format-specific metadata
            └── README.md            ← what this template produces, what assumptions it makes
```

Example for RHEL × password_complexity × kickstart:

```
portal/golden-image/library/linux_rhel/password_complexity/kickstart/
├── template.j2          ← post-section script for /etc/login.defs +
│                          /etc/security/pwquality.conf
├── defaults.yaml        ← min_length: 12  require_upper: true  …
├── verify.sh            ← chroot mount + opa eval against extracted facts
├── meta.yaml            ← supports RHEL 8.x, 9.x; requires kickstart ≥ Anaconda 32.x
└── README.md
```

### 3.3 Template composition

A single image may need to satisfy many control intents — a customer's
typical baseline policy includes password complexity + audit logging
+ SSH hardening + service hardening + audit retention + …  The
generator **composes** the templates rather than running them
sequentially:

For each `(image_format, target_vendor)` the customer is building:

1. Collect all `(abstract_control_key, parameters)` from every
   published customer policy in scope for that target vendor.
2. For each `abstract_control_key`, render its template fragment with
   the parameters.
3. Concatenate the fragments into the appropriate section of the
   final image artifact:
   - Kickstart: `%post --interpreter=/bin/bash` block
   - cloud-init: `runcmd` + `write_files` + `users` sections
   - Packer: provisioner `ansible` block + `file` provisioners
   - Containerfile: ordered `RUN` + `COPY` directives
   - unattend.xml: `<RunSynchronousCommand>` sequence + reg loads
4. Run static validation per format (`ksvalidator`, `cloud-init schema`,
   `packer validate`, `docker build --dry-run`, `WIM check`).
5. Sign the artifact with the Portal authoritative key.
6. Commit to the customer git bucket (path: `<framework>/golden-images/<format>/<image-set-name>/`).

### 3.4 IR-parameter handoff (same pattern as Rego + remediation)

```yaml
# customer's IR (from policy ingestion §10)
control_intents:
  - abstract_control_key: password_complexity
    parameters:
      min_length: 12
      require_upper: true
      max_age_days: 90
```

```jinja
# rendered template for linux_rhel × password_complexity × kickstart
%post --interpreter=/bin/bash
set -euo pipefail
# Auto-generated by Portal — source customer_policy {{ customer_policy_id }} v{{ version_semver }}
echo "PASS_MIN_LEN     {{ min_length }}" >> /etc/login.defs
echo "PASS_MAX_DAYS    {{ max_age_days }}" >> /etc/login.defs
cat > /etc/security/pwquality.conf <<EOF
minlen = {{ min_length }}
ucredit = {{ "-1" if require_upper else "0" }}
EOF
%end
```

**One template, N customer-specific values.** Same library, every
customer's image config tuned to their IR.

---

## 4. The generator

Hybrid engine — same shape as Rego (Phase 1-4) and remediation
(Phase 5):

```python
def generate_image_config(customer_policy_set, target_vendor, image_format):
    # Collect all in-scope control intents
    intents = collect_intents(customer_policy_set, target_vendor)
    fragments = []
    method_per_intent = {}
    confidences = []

    for intent in intents:
        template = lookup_image_template(
            intent.abstract_control_key,
            target_vendor,
            image_format,
        )
        if template and template.engine == 'jinja2':
            fragment = jinja_render(template.body, intent.parameters)
            method = 'template_mapped'
            confidence = 0.95
        elif template and template.engine == 'llm_with_skeleton':
            fragment = llm_generate_fragment(template.body, intent.parameters)
            method = 'llm_with_skeleton'
            confidence = 0.75
        else:
            fragment = llm_generate_fragment(
                generic_image_prompt(intent.abstract_control_key, target_vendor, image_format),
                intent.parameters,
            )
            method = 'llm_fallback'
            confidence = 0.55

        fragments.append(fragment)
        method_per_intent[intent.abstract_control_key] = method
        confidences.append(confidence)

    composed = compose_into_format(image_format, fragments)
    static_validate(image_format, composed)  # ksvalidator / cloud-init schema / packer validate / etc.
    signed = sign_with_portal_key(composed)
    overall_confidence = min(confidences)  # weakest link

    return signed, overall_confidence, method_per_intent
```

**Confidence + per-intent generation method tagged** on the artifact
header comment so customer review (§5) can flag low-confidence
sections.

### 4.1 Static validation per format

Every generated artifact passes a syntactic validator before being
offered to the customer:

| Format | Validator |
|---|---|
| Kickstart | `ksvalidator <file>` (from `pykickstart`) |
| cloud-init | `cloud-init schema --config-file <file>` |
| Packer | `packer validate <file>` |
| Containerfile | `buildah parse-image` or `podman build --no-cache --dry-run` |
| unattend.xml | XSD validation against MS-provided schema |
| GPO XML | `LGPO.exe /validate <file>` (on a Windows runner) |
| Network device config | Vendor-specific config parser (Cisco `parser_config`, NXOS validator, etc.) |

A static-validation failure surfaces in the review UI as a hard error
(can't approve) — distinct from a low-confidence warning.

---

## 5. Customer review + approval

Same shape as policy ingestion review (§11 there) and remediation
review (§5 there):

1. Customer triggers generation: `POST /api/portal/v1/tenants/{id}/golden-images/generate` with `(target_vendor, image_format, customer_policy_set, image_set_name)` parameters.
2. Generator runs; produces signed artifact + provenance metadata.
3. Notification to control_owner_user_id + Account Owner CC.
4. Owner opens review UI:
   - Rendered artifact preview (with syntax highlighting per format)
   - Per-intent breakdown: which control_intent contributed which lines, with confidence + generation method flag
   - Diff vs previous version (if updating)
   - List of customer policies the artifact covers + versions
5. Owner can:
   (a) Approve → artifact lands in tenant git bucket, ready for CI/CD pickup
   (b) Edit → save as customer-modified version, re-validate, re-submit
   (c) Reject + reason → audit log; no artifact landed
6. Audit log captures action with MFA-asserted actor identity.

### 5.1 Tier-aware approval gates

Same per-tier defaults as remediation review:

| Tier | Default gate |
|---|---|
| Free | Auto-approve after 24h preview window (low-risk policies only) |
| Standard | Owner manual approval |
| Premium | Owner + change-management webhook approval |
| Air-gapped | Bundle export; customer's CM runs build |

Policy-engine-driven (§2 of policy ingestion design) — no hardcoded gates.

---

## 6. Build attestation contract

The customer's CI/CD MUST emit a build attestation after every
successful image build that consumed a Portal-generated artifact.
This is the chain-of-custody anchor.

### 6.1 Attestation format

Following the **in-toto / SLSA Level 3** spec:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "image", "digest": {"sha256": "<image_sha>"}}
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://portal.aac/v1/golden-image",
      "externalParameters": {
        "image_format": "packer_aws_ami",
        "target_vendor": "linux_rhel",
        "customer_policy_set": [
          {"customer_policy_id": "...", "version_semver": "v1.2"},
          ...
        ],
        "portal_template_sha": "sha256:...",
        "base_image_sha": "sha256:..."
      },
      "resolvedDependencies": [
        {"name": "portal-artifact", "digest": {"sha256": "..."}, "uri": "https://portal.aac/v1/tenants/<id>/golden-images/<id>/config"},
        {"name": "base-image", "digest": {"sha256": "..."}}
      ]
    },
    "runDetails": {
      "builder": {"id": "https://customer.example/ci/<job_id>"},
      "metadata": {
        "invocationId": "<ci_invocation_id>",
        "startedOn": "...",
        "finishedOn": "..."
      }
    }
  },
  "portal_signature": "<ed25519 signature by Portal authoritative key over the canonical JSON>"
}
```

### 6.2 Attestation flow

```
Customer CI/CD:
  1. Pull signed Portal artifact via per-tenant token
  2. Verify Portal signature against pre-shared Portal public key
  3. Pull base image (verify its sha)
  4. Run build (Packer / cloud-init / docker build / etc.)
  5. Produce final image; capture its sha
  6. Build attestation JSON per §6.1
  7. POST attestation to Portal:
       POST /api/portal/v1/tenants/{tenant_id}/golden-images/{config_id}/attestations
       Body: signed attestation
  8. Portal verifies its own signature on the underlying artifact + records the new image_sha

Portal updates customer_golden_image_builds with the attestation
and emits an event to the customer's dashboard.
```

### 6.3 What the customer's CI/CD needs to do

We ship reference pipelines for the four main CI systems:

| CI System | Reference pipeline |
|---|---|
| GitHub Actions | `actions/portal-golden-image-build@v1` (composite action) |
| GitLab CI | `portal-golden-image-build.gitlab-ci.yml` (include file) |
| Tekton | `portal-golden-image-build` Task + Pipeline |
| Jenkins | shared library `portal-golden-image` |

Each reference does the same six steps above. Customers using other
CI systems (Azure Pipelines, AWS CodeBuild, Buildkite) write their
own pipeline from a documented contract; the contract is the
attestation format, not the CI implementation.

---

## 7. Image lifecycle: rebuild on policy update

When a customer publishes a new version of a policy that has a golden
image set built against the older version, the Portal:

1. Marks the affected `customer_golden_image_builds` rows as
   `policy_version_drift_detected = true`.
2. Surfaces a banner on the dashboard: "*5 image sets are now based on
   outdated policy versions. Rebuild?*"
3. Optional auto-trigger: customer's CI webhook fires automatically
   (default: opt-in per image set).

The lifecycle is deliberately **not** "automatically rebuild on every
policy update" — customer CI cycles cost money, and a typo in a
policy version 3 followed by a fix in version 4 should produce one
rebuild not two. The default is "let the customer decide when to
rebuild."

### 7.1 Image revocation

When a Portal-generated artifact is identified as having a security
bug — e.g., the LLM-fallback generated incorrect Rego that allowed a
control to be silently bypassed — the customer needs to know fast:

- Portal calls an immediate `POST /api/portal/v1/tenants/{id}/golden-images/{id}/revoke` on the affected artifact
- The customer's dashboard shows a banner: "*This image set has been revoked. All built images derived from it should be rebuilt.*"
- The artifact in the customer git bucket is marked `status: revoked` (kept for audit trail; NOT deleted)
- Customer notification + escalation to control_owner_user_id

Revocation is rare but must be airtight; it's part of how we earn
trust as the policy supply line.

---

## 8. AAC integration

### 8.1 Built image gets immediately assessed

The customer's CI/CD, after building + signing the image, should:

1. Provision an instance from the image (in a sandbox VPC / test cluster)
2. Wait for first-boot completion (cloud-init done / sysprep done)
3. Run AAC assessment against the running instance
4. Compare the assessment compliance % against the policy versions the image was built against

Step 4 is the **measurable closed loop**: did the image we just built
actually achieve compliance with the policy it was generated from? A
yes-or-no answer signed by the Portal.

We provide a reference test playbook (`ansible/playbooks/golden_image_assessment.yml`) the customer's CI runs as the last step of build. If the assessment fails, the image fails CI (won't be promoted to production registry).

### 8.2 First-boot AAC enrollment

Generated images include a first-boot hook that:

1. Registers the new instance with the customer's AAC inventory (`aac-portal-bridge` inventory push, or AAP callback if AAP is reachable)
2. Tags the instance with the source image SHA + policy version set it was built from
3. Triggers an initial assessment against the policies the image was built for

This ties freshly-deployed instances into AAC immediately. The
"born compliant" claim is verified within minutes of provisioning.

### 8.3 Air-gap / offline build accommodation

For air-gapped customers, the Portal cannot reach the customer CI; we
ship a different flow:

1. Operator signs + exports the Portal artifact bundle (out-of-band: signed tarball delivered via courier/SFTP/DVD)
2. Customer's internal CI builds the image from the bundle
3. Customer's internal team produces the attestation in the same format (with their own signing key derived from a Portal-issued public/private key escrow)
4. Attestation is delivered back out-of-band (next bundle exchange)

The attestation contract is unchanged; only the delivery transport
changes. This matters for FedRAMP / classified customers who can't
have direct Portal CI access.

---

## 9. Data model additions

Extending the policy ingestion design (§6 + the remediation design §8):

### `customer_golden_image_configs`

The customer-side "definition" of an image set — the set of customer
policies it's built from + target_vendor + image_format.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | FK |
| `name` | text | Customer-supplied (e.g., "Production RHEL 9 baseline") |
| `description` | text | |
| `image_format` | text | `kickstart`, `cloud_init`, `packer_aws_ami`, `packer_azure_image`, `packer_gcp_image`, `containerfile`, `unattend_xml`, `vcenter_template`, `cisco_ios_startup`, `kubernetes_manifest` |
| `target_vendor` | text | `linux_rhel`, `linux_ubuntu`, `windows_server`, etc. |
| `customer_policy_id_set` | uuid[] | The policies whose IRs feed this image |
| `current_artifact_storage_key` | text | Git path to the current signed artifact |
| `current_artifact_sha256` | text | |
| `version_semver` | text | Bumped on every regenerate |
| `status` | enum | `draft`, `published`, `revoked`, `archived` |
| `auto_rebuild_on_policy_update` | bool | Default false; customer opt-in |
| `auto_rebuild_webhook_url` | text | nullable; the customer's CI webhook |
| `tenant_attestation_signing_key_fingerprint` | text | for air-gap; nullable |
| `created_by` | uuid | FK |
| `created_at` | timestamptz | |
| `updated_at` | timestamptz | |

### `customer_golden_image_builds`

Each successful customer CI build emits an attestation that lands here.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | FK |
| `customer_golden_image_config_id` | uuid | FK |
| `image_sha256` | text | The final image SHA |
| `built_from_config_artifact_sha` | text | Which Portal artifact the build was based on |
| `policy_version_set_json` | jsonb | Snapshot of (customer_policy_id, version_semver) the image was built against |
| `attestation_json` | jsonb | Full in-toto / SLSA attestation |
| `attestation_verification_status` | enum | `verified`, `signature_invalid`, `policy_mismatch`, `pending` |
| `policy_version_drift_detected` | bool | Set to true when a member of policy_version_set is no longer current |
| `assessed_compliance_percentage` | float | Optional — populated when the customer's CI runs §8.1 post-build assessment |
| `builder_identity` | text | From attestation (CI job URL) |
| `built_at` | timestamptz | From attestation |
| `recorded_at` | timestamptz | When Portal received the attestation |

### Extension to `target_mappings`

Adds three columns (forward-compatible from policy ingestion §6):

| Column | Notes |
|---|---|
| `image_engine` | `jinja2`, `llm_with_skeleton`, `llm_prompt`, `none` |
| `image_format` | matches `customer_golden_image_configs.image_format` |
| `image_quality_grade` | `library_v1`, `experimental`, `community`, `deprecated` |
| `image_template_body` | text — the Jinja template OR LLM skeleton |

---

## 10. API surface (new endpoints)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/portal/v1/tenants/{id}/golden-images` | List image configs for the tenant |
| POST | `/api/portal/v1/tenants/{id}/golden-images` | Create a new image config (specifies policies, target vendor, format) |
| GET | `/api/portal/v1/tenants/{id}/golden-images/{id}` | Detail view with current artifact + build history |
| POST | `/api/portal/v1/tenants/{id}/golden-images/{id}/generate` | Trigger generation of the signed artifact |
| GET | `/api/portal/v1/tenants/{id}/golden-images/{id}/config` | Get the current signed artifact for the customer's CI to consume |
| PATCH | `/api/portal/v1/tenants/{id}/golden-images/{id}` | Customer edit of the generated artifact before approval (low-confidence cases) |
| POST | `/api/portal/v1/tenants/{id}/golden-images/{id}/approve` | Owner approves; artifact published to git bucket |
| POST | `/api/portal/v1/tenants/{id}/golden-images/{id}/revoke` | Mark artifact + derived images revoked |
| POST | `/api/portal/v1/tenants/{id}/golden-images/{id}/attestations` | Customer CI posts a build attestation |
| GET | `/api/portal/v1/tenants/{id}/golden-images/{id}/attestations` | Verify + list attestations |
| GET | `/api/portal/v1/tenants/{id}/golden-images/{id}/drift` | List built images whose underlying policy version_set has updated |

---

## 11. Frontend pages

| Route | Purpose |
|---|---|
| `/golden-images` | Dashboard: per-image-config status + recent builds + drift count |
| `/golden-images/new` | Wizard to create a new config: pick policies + target vendor + format |
| `/golden-images/{id}` | Detail: current artifact preview, build history, drift status, attestation chain |
| `/golden-images/{id}/review` | Approval review of generated artifact (per-intent breakdown + per-intent confidence) |
| `/golden-images/{id}/builds/{build_id}` | Per-build attestation + assessment result + status |

---

## 12. Open questions (tweak as we go)

| # | Question | Default for MVP |
|---|---|---|
| 1 | Which image formats land in MVP starter library? | **Kickstart + cloud-init + Packer + Containerfile + unattend.xml** (the five most common; ~80% of customer cases) |
| 2 | Auto-rebuild on policy update — opt-in or opt-out? | **Opt-in** — customer's CI cycles cost money; let them decide |
| 3 | Attestation signature scheme — ed25519 (modern, fast) or RSA (broader tooling) | **Both supported via in-toto envelope**; default ed25519 |
| 4 | First-boot assessment integration with AAC — required for image-set "verified" badge? | **Recommended, not required** for MVP; required for Premium tier verified badge |
| 5 | Network device images — startup-config baking vs day-1 config push | **Startup-config baking** is the closer parallel to "born compliant"; day-1 push is the fallback for legacy devices |
| 6 | Kubernetes admission control (PSP / Gatekeeper constraints) — same generator or separate piece? | **Same generator**; PSPs are just another image format |
| 7 | Multi-arch images (arm64 + amd64) | **Per-arch artifact in MVP**; multi-arch manifest generation later |
| 8 | Per-customer Portal signing key vs single Portal key | **Single Portal authoritative key**; per-tenant signing layer comes if a customer demands tenant-key-control |
| 9 | Customer-side attestation storage — Portal store-and-forward or customer-managed? | **Portal stores**; customer can optionally also push to their own ledger (sigstore Rekor, e.g.) |
| 10 | Air-gap bundle exchange cadence | **Per-customer**; default weekly; tunable per contract |

---

## 13. Phased implementation plan

**Phase 6** of the policy ingestion phased plan (§22 there).  
Two sprints, **after Phase 5** (remediation) ships.

### Sprint 11 — generator + library

1. New tables: `customer_golden_image_configs`, `customer_golden_image_builds`, plus extension columns on `target_mappings`
2. Image template library — 10 abstract controls × 3 vendor families × 4-5 image formats = ~150 templates
3. Generator service (`api/src/policy_ingestion/golden_image_generator.py`)
4. Static-validation harness per format (`ksvalidator`, `cloud-init schema`, `packer validate`, `buildah parse-image`, XSD)
5. Signing service with the Portal authoritative key
6. Signed-artifact endpoints

### Sprint 12 — attestation + customer integration

7. Frontend `/golden-images` pages
8. Approval flow with MFA
9. Attestation ingestion endpoint + signature verification + drift detection
10. Reference CI pipelines for GitHub Actions / GitLab CI / Tekton / Jenkins
11. First-boot AAC enrollment hook (script + Ansible playbook customer embeds in their image)
12. End-to-end soak test (sandbox tenant builds a RHEL 9 AMI + assesses post-deploy)

---

## 14. References

### Builds on / depends on

- `policy_ingestion_design.md` v1.3 — Phase 6 follows Phase 1-4 ship
- `remediation_generator_design.md` v1.0 — same generator pattern, attestation pattern
- `portal_capabilities_brief.md` §11.2 Piece 25 (now generic golden image work)
- `portal_security_baseline.md` (forthcoming) — signing key custody addressed there

### Standards adopted

- **SLSA v1.0** — Supply-chain Levels for Software Artifacts; we target Level 3+ for the build provenance
- **in-toto v0.9** — attestation envelope format
- **TUF (The Update Framework)** — pattern for key rotation in the air-gap flow
- **OpenSSF Sigstore** — optional customer-side attestation forwarding to Rekor

### Industry context

- **Packer** (HashiCorp) — primary tool for multi-cloud image builds
- **Kickstart** (Anaconda) — RHEL automated install
- **cloud-init** — Ubuntu / cloud-image first-boot
- **buildah / podman** — OCI image build tooling
- **MS Deployment Toolkit** — Windows unattended install lineage

---

**Authored with Claude (Anthropic).**
