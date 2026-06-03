# AAC Customer Portal — Policy Ingestion Design

**Audience:** Internal planning — engineering, product, security review.
**Purpose:** Design specification for the customer policy ingestion
feature (Piece 46 in `portal_capabilities_brief.md` §11.2 /
TaskCreate #46). Defines what we build for the MVP, what we defer,
and the decisions we'll revisit as real usage informs them.
**Drafted:** 2026-06-02
**Version:** v1.1

## Revision history

| Version | Date | Change |
|---|---|---|
| v1.0 | 2026-06-02 | Initial MVP design. Bidirectional ingestion (prose-to-Rego + fork-and-tweak); hybrid conversion (template + LLM fallback); per-customer Rego buckets organized by compliance framework; Portal-side bundle assembly; drift detection against the standard `rego_policy_libraries`; RBAC (Account Owner / Editor / Viewer) with TOTP + WebAuthn MFA. |
| v1.1 | 2026-06-02 | **Reframed as the full compliance loop**, not just conversion. The Portal now owns the complete sequence: written policy → Rego → live assessment → gap mitigation playbooks → golden image generation → ongoing assessment → audit-ready reports. Added §19 (closed loop), §20 (audit reports), extended phased plan to 7 phases. Same MVP boundary (Phases 1-4); the loop extensions are Phases 5-7. |

---

## 1. Requirements summary

From the customer conversation that drove this design:

1. Customer uploads a written policy in **docx, pdf, md, html, etc.**
2. Portal converts the prose into **Rego v1 code**
3. Generated Rego stored in a **customer-specific artifact store** for use by the customer's AAC instance
4. **Updates and revisions** — date and version numbers tracked per policy
5. **Multiple users per customer** with **role-based access** to their bucket
6. **Multifactor authentication** capability
7. **Customer account owner** role
8. **One customer policy → N target-system Rego files.** A single "Password Policy" must produce separate Rego for Windows, Linux, mainframe, network gear, etc. — same intent, N implementations.
9. **Adjusting existing policies as well as creating new ones.** Customer can fork standard CIS / NIST / ISO Rego from the `rego_policy_libraries` and overlay their specific tweaks.
10. **Bucket per compliance standard.** Customer's Rego is organized by the framework it belongs to (cis_rhel9, cis_m365, iso27001, corporate, etc.).

---

## 2. MVP scope

The minimum-viable feature set we commit to in this design — tweakable
as real usage informs us:

1. Customer enrolls in frameworks (depends on Piece 15)
2. Customer's AAC inventory tells Portal which target systems they have (already shipped — Pieces 2-3 / `tenant_inventory_catalog`)
3. **Path A — prose-to-Rego**: upload → LLM extracts IR → hybrid template-or-LLM Rego generator → per-target Rego files → customer review → publish → bucket
4. **Path B — fork-and-tweak**: browse standard library by enrolled framework → fork a standard Rego → side-by-side diff editor → save as overlay → customer review → publish → bucket
5. **Bundle assembly** (Portal-side for MVP): merge standard library + customer overlays + customer-original adds → signed bundle for the customer's AAC bridge to pull
6. **Drift detection** when the standard library updates — surface "your overlay is based on an older version" alerts
7. **RBAC**: Account Owner, Editor, Viewer
8. **MFA**: TOTP (required for Owner + Editor) + WebAuthn (recommended)
9. **Audit log** of every policy change

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ CUSTOMER (browser)                                              │
│  ┌─────────────────┐   ┌─────────────────┐   ┌──────────────┐   │
│  │ Upload prose    │   │ Browse standard │   │ Manage users │   │
│  │  policy doc     │   │  library + fork │   │  + MFA       │   │
│  └────────┬────────┘   └────────┬────────┘   └──────┬───────┘   │
└───────────┼────────────────────┼───────────────────┼────────────┘
            │ Path A             │ Path B            │
┌───────────▼────────────────────▼───────────────────▼────────────┐
│ PORTAL — FastAPI                                                │
│  ┌──────────────┐  ┌──────────────────────┐  ┌──────────────┐   │
│  │ Doc parser   │  │ Fork-and-tweak       │  │ User + MFA   │   │
│  │  → plaintext │  │  diff editor backend │  │  + audit log │   │
│  └──────┬───────┘  └──────────┬───────────┘  └──────────────┘   │
│         │                     │                                 │
│  ┌──────▼─────────────┐       │                                 │
│  │ LLM IR extractor   │       │                                 │
│  │  → control_intents │       │                                 │
│  └──────┬─────────────┘       │                                 │
│         │                     │                                 │
│  ┌──────▼─────────────────────▼─────┐                           │
│  │ Hybrid Rego generator:           │                           │
│  │  1. Template-mapped where lib    │                           │
│  │     covers (abstract_control ×   │                           │
│  │     target_system)               │                           │
│  │  2. LLM-fallback otherwise       │                           │
│  └──────┬───────────────────────────┘                           │
│         │ produces N per-target Rego                            │
│         │                                                       │
│  ┌──────▼──────────────────────────┐                            │
│  │ Customer policy review queue    │                            │
│  │  (draft → reviewed → published) │                            │
│  └──────┬──────────────────────────┘                            │
│         │                                                       │
│  ┌──────▼─────────────────────┐    ┌──────────────────────┐     │
│  │ Per-customer git repo      │    │ Drift detector       │     │
│  │  (Portal-hosted, 1 per     │    │  (alerts when std    │     │
│  │   tenant)                  │    │   library updates)   │     │
│  │  bucket structure ↓        │    └──────────────────────┘     │
│  │  tenant/                   │                                 │
│  │   ├── cis_rhel9/           │                                 │
│  │   ├── cis_m365/            │                                 │
│  │   ├── iso27001/            │                                 │
│  │   └── corporate/           │                                 │
│  └──────┬─────────────────────┘                                 │
│         │                                                       │
│  ┌──────▼───────────────────────────┐                           │
│  │ Bundle assembler                 │                           │
│  │  std lib + customer overlays +   │                           │
│  │  customer originals → signed tar │                           │
│  └──────┬───────────────────────────┘                           │
└─────────┼───────────────────────────────────────────────────────┘
          │ HTTPS (per-tenant token + bundle scope)
┌─────────▼───────────────────────────────────────────────────────┐
│ CUSTOMER AAC bridge                                             │
│  Pulls signed bundle → verifies signature →                     │
│  reloads OPA in bundle mode (depends on task #45)               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. The two ingestion paths

### Path A — prose-to-Rego

User journey:
1. User uploads `Acme Password Standard v2.0.pdf` (or .docx, .md, .html)
2. Portal parses the file → plaintext
3. LLM extracts canonical **Intermediate Representation (IR)** — a structured JSON of control intents
4. Portal cross-references IR against the customer's enrolled frameworks + inventory to infer target systems
5. Portal generates N per-target Rego files via the hybrid generator
6. Customer reviews IR (one screen) + each generated Rego (tabbed UI) → approves
7. Portal commits to customer git bucket with semver bump
8. Bundle assembler picks up the new files on next bundle build

### Path B — fork-and-tweak

User journey:
1. User browses the standard library, filtered to their enrolled frameworks
2. Selects a Rego file (e.g., `cis_rhel9/ssh_validation.rego`)
3. "Fork" creates a tenant-scoped overlay row in `customer_policy_overlays`
4. Portal opens a side-by-side diff editor: **standard** | **your version**
5. User edits the right pane (with Rego v1 syntax linting)
6. User adds an optional prose annotation explaining the change (audit trail)
7. User submits → review queue → publish → commits to customer git bucket as overlay
8. Bundle assembler shadows the standard file with this overlay on next bundle build

---

## 5. Bucket organization

Per-tenant git repo, structured by framework:

```
tenant-acme/
├── cis_rhel9/
│   ├── filesystem_validation.rego       ← OVERLAY (forked from standard)
│   ├── ssh_validation.rego              ← OVERLAY
│   └── _custom_audit_retention.rego     ← CUSTOMER-ORIGINAL
├── cis_windows_2022/
│   └── _custom_password_policy.rego     ← from a Path A upload
├── cis_m365/
│   └── (empty — Acme inherits the entire standard)
├── iso27001/
│   └── _custom_data_classification.rego
├── corporate/                            ← Pure-corporate, not tied to a framework
│   └── _custom_acceptable_use.rego
└── _manifest.yaml                       ← Bundle assembly metadata
```

Convention:
- File at `<framework>/<file>.rego` with the **same name as a standard library file** → **overlay** (shadows the standard)
- File at `<framework>/_<file>.rego` (leading underscore) → **customer-original** (no parent in the standard library)
- `corporate/` is a special bucket for org-specific policies not tied to any framework

---

## 6. Data model (new tables)

### `customer_policies`

The parent: one row per **uploaded prose document** or **fork-and-tweak initiative**.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | FK → tenants |
| `name` | text | Customer-supplied (e.g., "Acme Password Standard") |
| `framework_bucket` | text | One of `cis_rhel9`, `cis_m365`, `iso27001`, `corporate`, … |
| `policy_source` | enum | `prose_upload`, `forked_overlay`, `customer_original` |
| `source_file_storage_key` | text | Object-store key to the original upload (if Path A) |
| `source_file_mime` | text | `application/pdf`, `application/vnd.openxmlformats-officedocument...`, etc. |
| `ir_json` | jsonb | The canonical IR extracted by the LLM (Path A) |
| `parent_standard_ref` | text | If overlay: standard library SHA + path the customer forked from |
| `parent_standard_version` | text | Standard library version at fork time (e.g., `cis_rhel9-v2.0.0`) |
| `version_semver` | text | Customer's policy version (e.g., `v1.0`, `v1.1`) |
| `effective_date` | date | Customer-supplied effective date |
| `status` | enum | `draft`, `in_review`, `published`, `archived` |
| `created_by` | uuid | FK → tenant_users |
| `created_at` | timestamptz | |
| `updated_at` | timestamptz | |

### `customer_policy_targets`

The children: one row per **(customer_policy × target_system)** pairing.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `customer_policy_id` | uuid | FK → customer_policies |
| `target_system` | text | `linux`, `windows`, `cisco_ios`, `juniper`, `zos`, … |
| `target_subtype` | text | Optional (`rhel9`, `windows_server_2022`, …) |
| `rego_storage_key` | text | Git path under tenant bucket |
| `rego_content_sha256` | text | Integrity check |
| `generation_method` | enum | `template_mapped`, `llm_fallback`, `customer_authored` |
| `confidence_score` | float | 0.0-1.0, surfaced in review UI |
| `review_status` | enum | `pending`, `approved`, `rejected` |
| `published_in_bundle_sha` | text | First bundle SHA this Rego appeared in |
| `created_at` | timestamptz | |

### `abstract_controls`

Shared across all customers — the reusable library of control intents.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `key` | text | `password_complexity`, `audit_log_retention`, … (slug) |
| `display_name` | text | "Password complexity requirements" |
| `description` | text | What the abstract control covers |
| `domain` | text | `authentication`, `audit`, `network`, … |
| `parameters_schema` | jsonb | JSON Schema for the IR parameters (e.g., `min_length: int`) |

### `target_mappings`

Shared library: `(abstract_control × target_system) → Rego generation template`.

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `abstract_control_id` | uuid | FK → abstract_controls |
| `target_system` | text | matches `customer_policy_targets.target_system` |
| `target_subtype` | text | optional refinement |
| `template_engine` | enum | `jinja2`, `llm_prompt` |
| `template_body` | text | The Jinja template or LLM prompt skeleton |
| `input_contract_schema` | jsonb | What the generated Rego expects from Ansible facts |
| `quality_grade` | enum | `library_v1`, `experimental`, `deprecated` |

### `tenant_users`

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_id` | uuid | FK → tenants |
| `email` | text | unique within tenant |
| `display_name` | text | |
| `oidc_subject` | text | Subject claim from customer's IdP if SSO, NULL if username/password |
| `role` | enum | `account_owner`, `editor`, `viewer` |
| `mfa_enrolled` | bool | true if at least one factor enrolled |
| `mfa_required` | bool | enforced by role (owner + editor) |
| `last_login_at` | timestamptz | |
| `disabled_at` | timestamptz | nullable, soft-delete |

### `tenant_user_mfa_factors`

| Column | Type | Notes |
|---|---|---|
| `id` | uuid | PK |
| `tenant_user_id` | uuid | FK → tenant_users |
| `factor_type` | enum | `totp`, `webauthn`, `backup_codes` |
| `secret_hash` | text | bcrypt-style for TOTP secret; credential metadata for WebAuthn |
| `enrolled_at` | timestamptz | |
| `last_used_at` | timestamptz | |
| `revoked_at` | timestamptz | nullable |

### `policy_audit_log`

| Column | Type | Notes |
|---|---|---|
| `id` | bigserial | PK |
| `tenant_id` | uuid | |
| `tenant_user_id` | uuid | nullable (system actions) |
| `customer_policy_id` | uuid | nullable |
| `action` | text | `created`, `edited`, `approved`, `published`, `archived`, `bundle_built`, … |
| `details` | jsonb | Per-action payload |
| `at` | timestamptz | indexed |

---

## 7. API surface (new endpoints)

All scoped under `/api/portal/v1/tenants/{tenant_id}/policies/` and `/api/portal/v1/tenants/{tenant_id}/users/`. Auth: per-tenant bearer + per-user OIDC + MFA challenge for write operations.

| Method | Path | Purpose |
|---|---|---|
| POST | `/policies/uploads` | Upload prose doc (multipart); returns `customer_policy_id` + first IR pass |
| GET | `/policies/{id}/ir` | Get the IR for review |
| PATCH | `/policies/{id}/ir` | Customer edits the IR before generation |
| POST | `/policies/{id}/generate` | Run hybrid generator → produces per-target Rego rows |
| GET | `/policies/{id}/targets` | List per-target Rego entries with status |
| GET | `/policies/{id}/targets/{target_id}/rego` | Get a single generated Rego file content |
| PATCH | `/policies/{id}/targets/{target_id}/rego` | Customer edits the generated Rego before approval |
| POST | `/policies/{id}/targets/{target_id}/approve` | Approve one Rego |
| POST | `/policies/{id}/publish` | All targets approved → publish; bumps semver |
| POST | `/policies/{id}/archive` | Soft-archive (keeps history) |
| GET | `/policies/library` | Browse standard library filtered by tenant's enrolled frameworks |
| POST | `/policies/library/fork` | Fork a standard Rego → creates a `forked_overlay` customer_policy + draft target |
| GET | `/policies/drift` | List overlays whose parent standard has changed since fork |
| GET | `/bundles/current` | Get the current effective bundle for this tenant (signed tar) |
| GET | `/bundles/history` | Bundle version history |
| GET / POST | `/users` | List / create tenant users |
| PATCH / DELETE | `/users/{id}` | Update / soft-delete a tenant user |
| POST | `/users/{id}/mfa/enroll` | Begin MFA enrollment (TOTP secret + WebAuthn challenge) |
| POST | `/users/{id}/mfa/verify` | Verify enrollment |
| POST | `/auth/login` | Username/password (or OIDC redirect); returns intermediate token |
| POST | `/auth/mfa-challenge` | Submit TOTP / WebAuthn assertion; returns final bearer |

---

## 8. RBAC

Three roles for MVP. Role checks happen in FastAPI dependency middleware on every write endpoint.

| Capability | Account Owner | Editor | Viewer |
|---|:-:|:-:|:-:|
| Upload prose doc | ✅ | ✅ | — |
| Fork standard policy | ✅ | ✅ | — |
| Edit IR / Rego | ✅ | ✅ | — |
| Approve a generated Rego | ✅ | ✅ | — |
| Publish a policy | ✅ | ✅ | — |
| Archive a policy | ✅ | — | — |
| Browse standard library | ✅ | ✅ | ✅ |
| View any policy | ✅ | ✅ | ✅ |
| View audit log | ✅ | ✅ (own actions only) | — |
| Manage users (create, role-change, deactivate) | ✅ | — | — |
| Manage MFA factors (own) | ✅ | ✅ | ✅ |
| Force-reset other user's MFA | ✅ | — | — |
| Change account-level settings | ✅ | — | — |

Two distinct roles among writers (Owner vs Editor) because customers running compliance want to separate "operational policy author" from "account administrator." The Editor can do everything policy-related; only the Owner manages users and billing.

---

## 9. Authentication + MFA

### Authentication

Two paths supported in MVP:

1. **Username + password** (Portal-managed accounts) — for customers without SSO
2. **OIDC SSO** (delegate to customer's IdP — Okta, Auth0, Azure AD, Google Workspace) — for customers with an org IdP

OIDC SSO is the recommended path for Premium-tier customers — single point of identity, MFA enforcement comes from the IdP.

### MFA

Required for Account Owner and Editor; opt-in for Viewer.

**Factors:**

- **TOTP** (Time-based One-Time Password — Google Authenticator, Authy) — required minimum
- **WebAuthn** (hardware security keys + platform passkeys) — strongly recommended, optional
- **Backup codes** (10 single-use codes, generated at enrollment time) — required as a recovery path

**Login flow:**

```
1. User → POST /auth/login (username + password)
2. Portal verifies; returns 200 with intermediate_token (scope: mfa_challenge, TTL 5 min)
3. User → POST /auth/mfa-challenge (intermediate_token + TOTP code)
4. Portal verifies; returns 200 with bearer (full scopes, TTL configurable per tenant)
```

OIDC SSO flow piggybacks on the IdP's MFA — Portal accepts the OIDC token's `amr` claim as proof of MFA satisfaction and skips the Portal's MFA challenge.

**Storage:**
- TOTP secrets stored bcrypt-hashed in `tenant_user_mfa_factors`
- WebAuthn credential public keys stored as JSON
- Backup codes hashed; each consumed exactly once

---

## 10. Conversion pipeline

### Stage 1 — Document parsing

| File type | Parser |
|---|---|
| `.docx` | `python-docx` |
| `.pdf` | `pdfplumber` (better than `pypdf` for layout-aware text extraction) |
| `.md` / `.txt` | direct read |
| `.html` | `beautifulsoup4` |
| `.xlsx` / `.csv` (controls listed in a table) | `openpyxl` / built-in |

Output: clean plaintext + (optional) per-section structure if the document had headings.

### Stage 2 — IR extraction (LLM)

Single LLM call. Prompt template (sketch):

```
You are extracting machine-actionable compliance controls from a written policy.

Read the following document and produce a JSON document conforming to this schema:
{
  "control_intents": [
    {
      "abstract_control_key": "<key from the library, OR 'unknown'>",
      "parameters": { ... per the library's parameters_schema, OR free-form if unknown },
      "source_quote": "<verbatim sentence from the document this came from>",
      "confidence": <0.0–1.0>
    }
  ],
  "metadata": {
    "policy_name_inferred": "...",
    "effective_date_inferred": "YYYY-MM-DD or null",
    "owner_inferred": "..."
  }
}

Document:
<plaintext doc here>

Known abstract control keys: <list from the library>
```

Reasonable LLM choices: Anthropic Claude (Sonnet 4 or higher), OpenAI GPT-4 class. The Portal abstracts over the provider so we can swap later.

Output: validated IR JSON stored in `customer_policies.ir_json`.

### Stage 3 — Target inference

Cross-reference the IR against the tenant's `tenant_inventory_catalog`:

- IR says "password complexity"
- Customer's inventory shows: 100 RHEL 9 hosts, 50 Windows Server 2022 hosts, 20 Cisco IOS-XE devices
- Portal infers targets: `linux/rhel9`, `windows/server_2022`, `cisco_ios`

Customer can override (add/remove targets) before generation.

### Stage 4 — Hybrid generation

For each `(abstract_control, target_system)`:

```python
def generate(abstract_control_key, target_system, target_subtype, parameters):
    template = lookup_target_mapping(abstract_control_key, target_system, target_subtype)
    if template and template.template_engine == "jinja2":
        return jinja_render(template.template_body, parameters), "template_mapped", 0.95
    elif template and template.template_engine == "llm_prompt":
        return llm_generate(template.template_body, parameters), "llm_fallback_with_skeleton", 0.75
    else:
        return llm_generate(generic_prompt(abstract_control_key, target_system, parameters), parameters), "llm_fallback", 0.55
```

Each generated Rego carries `generation_method` + `confidence_score` for the review UI.

### Stage 5 — Validation

Every generated Rego is validated:
1. `opa check` runs in the Portal backend; reject if syntax fails
2. Static analysis: does it use `import rego.v1`? Does it have `default compliant := false`? Does it return a `compliance_report`?
3. If validation fails, mark target as `review_status=rejected` with a clear error message; allow customer to edit and re-validate

Validation does NOT mean "produces correct results" — only that the Rego is syntactically valid and structurally conforms to the AAC contract.

---

## 11. Review workflow

```
[draft] ─┬→ [in_review] ─┬→ [published] ─→ [archived]
         │               │                ▲
         │               └→ [rejected] ───┘
         │                       │
         └───────────────────────┘
         (customer iterates back to draft)
```

States are per-policy (`customer_policies.status`). Per-target review status is independent (`customer_policy_targets.review_status`). A policy advances to `published` only when *all* targets are `approved`.

Account Owner + Editor can move to published. Auditing of who-approved-what lives in `policy_audit_log`.

---

## 12. Bundle assembly (Portal-side)

Triggers:
1. A customer policy publishes (their bundle rebuilds)
2. Standard library updates (every tenant with overlays on the changed file gets a "drift detected" event + bundle rebuilds)
3. Manual rebuild via API

Process:

```python
def build_bundle(tenant_id):
    enrolled = get_framework_enrollments(tenant_id)
    bundle_files = {}
    for framework in enrolled:
        # Start with standard library
        for path, content in standard_library_files(framework):
            bundle_files[path] = (content, "standard", standard_sha(framework))
        # Apply overlays (shadow standard files)
        for overlay in get_published_overlays(tenant_id, framework):
            bundle_files[overlay.path] = (overlay.content, "overlay", overlay.sha)
        # Append customer-original adds
        for original in get_published_customer_originals(tenant_id, framework):
            bundle_files[original.path] = (original.content, "original", original.sha)
    tarball = tar(bundle_files)
    signature = sign(tarball, portal_signing_key)
    bundle_sha = sha256(tarball)
    store(tenant_id, bundle_sha, tarball, signature)
    return bundle_sha
```

The bridge pulls the bundle via `GET /bundles/current`, verifies the signature with the operator's pre-shared public key, and reloads OPA in bundle mode (depends on AAC task #45).

---

## 13. Drift detection

When `rego_policy_libraries` updates (a new SHA is published for a framework):

1. Portal cron job (every hour) checks the upstream sha
2. For each customer overlay whose `parent_standard_ref` matches the *old* sha:
   - Compute diff between old standard and new standard at that file path
   - If the diff is empty (file unchanged in the upstream update), advance the overlay's `parent_standard_ref` silently
   - If the diff is non-empty, emit a `drift_detected` event for that overlay
3. Customer sees a UI banner: *"Your overlay of `cis_rhel9/ssh_validation.rego` is based on v2.0.0 of the standard. v2.0.1 changed N lines. Review your overlay?"*
4. Customer can: (a) **accept upstream** (overlay obsoleted, falls back to standard), (b) **rebase** (merge upstream changes into overlay), (c) **ignore for now** (overlay stays on old parent, dismissable but re-fires after 30 days)

---

## 14. Versioning model

| Object | Versioning scheme |
|---|---|
| `customer_policies.version_semver` | Semver per-policy. Bumped on publish: minor for non-breaking, major for breaking (customer-judged). |
| Overlay rega `parent_standard_version` | Tracks the standard version + sha the overlay was forked from. e.g. `cis_rhel9-v2.0.0@5eace2c`. |
| Customer's effective bundle | Date + sha. e.g. `acme-2026-06-02-1a3f7c2e`. Surfaced on the Portal dashboard + audit log. |
| Standard library | Tracked by the `rego_policy_libraries` submodule sha. |

**Audit-grade lineage:** Any published bundle's full provenance can be reconstructed from:
- The bundle sha → which Portal commit produced it
- The Portal commit → list of (customer_policy_id, version_semver) included
- Each customer_policy → uploaded source file + IR + per-target Rego shas
- Each overlay → the standard library version + path forked from

This is the chain of custody an auditor will want when assessing "are you running the policies you say you're running?"

---

## 15. Frontend pages (React)

| Route | Purpose |
|---|---|
| `/policies` | List of all customer policies for the tenant, filterable by framework / status |
| `/policies/upload` | Path A — upload a prose doc, monitor parsing + IR extraction |
| `/policies/{id}/review` | Path A review screen — IR view + per-target Rego tabs + approve/reject |
| `/policies/library` | Browse standard library by enrolled framework |
| `/policies/library/{path}/fork` | Path B — opens side-by-side diff editor; saves as overlay |
| `/policies/{id}/history` | Version history for one policy |
| `/policies/{id}/drift` | If overlays drift detected, show diff vs current standard |
| `/policies/audit` | Filterable audit log (per-tenant) |
| `/users` | Tenant user list — Owner can manage |
| `/users/me/mfa` | Enroll / re-enroll MFA factors |
| `/account` | Account-level settings — Owner only |

Component library: continues the existing `frontend/src/pages/` pattern (Vite + Tailwind + TanStack Query + Axios from Piece 11).

---

## 16. Open questions (things to tweak as we go)

These are deferred to "tweak as we learn":

| # | Question | Default for MVP | When to revisit |
|---|---|---|---|
| 1 | Should bundle merge happen Portal-side or customer-side? | **Portal-side** | When air-gapped / sovereign customers sign up |
| 2 | Should the customer's Path B fork-edit show the standard inline-readable or behind a "show standard" toggle? | Side-by-side default | After 5+ customers have used it |
| 3 | Should we extract IR per-control or per-document? | Per-document (one LLM call returns many control_intents) | If LLM cost becomes a meaningful line item |
| 4 | Should Editor be able to publish without Owner approval? | Yes — Editor publishes directly | If customers ask for approval workflow |
| 5 | Should we offer a "policy template marketplace" (operator-curated starter policies)? | Out of scope for MVP | Phase 2 |
| 6 | LLM provider — Anthropic Claude vs OpenAI vs both? | Claude (Sonnet 4 or higher) | When first cost/quality data exists |
| 7 | Should MFA backup codes be 6 or 10 digits? Length-vs-friction tradeoff. | 8 digits × 10 codes | Once we know enrollment friction |
| 8 | Should we cap the size of an uploaded policy doc? | 10 MB MVP cap | Increase if customers hit it |
| 9 | Should customers be able to roll back to a previous bundle? | Yes — `POST /bundles/rollback/{sha}` | MVP includes |
| 10 | How do we handle a customer who uploads a policy in a language other than English? | English-only MVP | After customer ask |

---

## 17. Phased implementation plan

### Phase 1 — foundations (sprints 1-2)

1. New tables in `api/migrations/` — `customer_policies`, `customer_policy_targets`, `tenant_users`, `tenant_user_mfa_factors`, `policy_audit_log`
2. Tenant user CRUD + RBAC middleware
3. TOTP MFA (enrollment + login flow) — defer WebAuthn to phase 2
4. Per-tenant git repo provisioning (Gitea or self-hosted git server; one repo per tenant on tenant onboarding)
5. Object storage for raw uploads (S3 or local equivalent)
6. Audit log writes

### Phase 2 — Path A end-to-end (sprints 3-4)

7. Document parsers for the 5 file types
8. Starter `abstract_controls` library — 10 controls × 4 target families = 40 mappings
9. LLM IR extractor (Anthropic Claude API call wrapper)
10. Hybrid Rego generator (Jinja template engine + LLM fallback)
11. Rego validation pipeline (`opa check` integration)
12. Frontend: upload page + review screen with per-target tabs
13. Customer publish → commit to tenant git repo
14. WebAuthn MFA (rounds out factor coverage)

### Phase 3 — Path B end-to-end (sprints 5-6)

15. Standard library browser frontend + filter by enrolled framework
16. Fork-and-tweak diff editor (CodeMirror with Rego syntax highlighting)
17. Overlay storage + bundle assembler that shadows standard with overlays
18. Drift detection cron + UI banners

### Phase 4 — bundle delivery + production hardening (sprints 7-8)

19. Bundle assembler: standard + overlay + original → signed tar
20. `GET /bundles/current` endpoint with per-tenant scope
21. AAC bridge update: pull + verify + reload OPA bundle mode (depends on task #45)
22. Drift-detection cron in production
23. Audit log dashboard
24. End-to-end soak test with a pilot customer

This is **8 sprints / ~16 weeks** for the MVP. Phase 1 is independent and parallelizable with Phase 2 prep. Phase 4 blocks on AAC task #45 (OPA bundle mode) landing first on the AAC side.

---

## 18. References

### Code (to be created)

- `api/migrations/006_policy_ingestion.sql` — new tables
- `api/src/routers/policies.py` — Path A and B endpoints
- `api/src/routers/tenant_users.py` — RBAC + MFA endpoints
- `api/src/policy_ingestion/parser.py` — document parsing
- `api/src/policy_ingestion/ir_extractor.py` — LLM IR extraction
- `api/src/policy_ingestion/generator.py` — hybrid Rego generator
- `api/src/policy_ingestion/templates/` — Jinja templates per (abstract_control × target_system)
- `api/src/policy_ingestion/validator.py` — `opa check` wrapper
- `api/src/policy_ingestion/bundle_assembler.py` — standard + overlays → signed tar
- `api/src/policy_ingestion/drift_detector.py` — cron job
- `frontend/src/pages/policies/` — React pages

### Documents this builds on

- `portal_capabilities_brief.md` §6.3 (Compliance-as-a-service core) and §11.2 Piece 46
- `portal_saas_lens_assessment.md` §2 (Security — tenant isolation principles)
- `portal_security_baseline.md` (to be populated — A2 will inform RBAC + MFA implementation)
- `portal_reliability_slo.md` §Surface 7 (Policy bundle delivery)
- `portal_operations_runbook.md` §3 (On-call) and §6 (Access control)

### Standards

- OWASP ASVS V2 (Authentication) — TOTP + WebAuthn implementation guidance
- OWASP ASVS V4 (Access Control) — RBAC implementation guidance
- IETF RFC 6238 — TOTP
- W3C WebAuthn Level 2 — WebAuthn implementation

---

**Authored with Claude (Anthropic).**

---

## 19. The compliance loop — beyond MVP

The MVP (Phases 1-4) ships **policy → Rego → bundle delivery**. The
strategic value, and what justifies the buyer's investment, is the
**full compliance loop** built on the same IR:

```
                  ┌─────────────────────────────────┐
                  │  Customer's written policy      │
                  └────────────┬────────────────────┘
                               │ Path A or B (§4)
                               ▼
                  ┌─────────────────────────────────┐
                  │  Canonical IR (§10)             │
                  └──────────┬────────┬────────┬────┘
                             │        │        │
        ┌────────────────────┘        │        └──────────────────┐
        │                             │                           │
        ▼                             ▼                           ▼
┌──────────────────┐          ┌─────────────────┐         ┌──────────────────┐
│ Rego validator   │          │ Remediation     │         │ Golden image     │
│ (MVP — Phase 2) │          │ playbooks       │         │ generator        │
│                  │          │ (Phase 5)       │         │ (Phase 6)        │
│ "Are we          │          │                 │         │                  │
│  compliant?"     │          │ "Make us        │         │ "Build images    │
└──────────────────┘          │  compliant."    │         │  that ARE        │
        │                     └────────┬────────┘         │  compliant from  │
        │ assesses                     │ runs on          │  the start."     │
        ▼                              ▼ existing infra   └──────────────────┘
┌──────────────────┐          ┌─────────────────┐                 │
│ AAC live         │          │ AAC remediation │                 │
│ assessment       │          │ workflow        │                 │
│ → compliance_    │          │ (Backup → Patch │                 │
│   results        │          │  → Validate     │                 │
│                  │          │  contract,      │                 │
│ → gap list       │          │  Piece 47)      │                 │
└──────────────────┘          └────────┬────────┘                 │
        │                              │                          │
        │                              │ resulting state          │
        │ ◄─────────── re-assess ──────┘                          │
        │                                                          │
        ▼                                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Audit-ready policy report (§20, Phase 7)                            │
│   - policy lineage + signature                                       │
│   - current assessment results                                       │
│   - gap history + mitigations applied                                │
│   - golden image attestations                                        │
│   - chain of custody                                                 │
└─────────────────────────────────────────────────────────────────────┘
```

Why this matters strategically:

| Capability | What it answers for the customer |
|---|---|
| Policy → Rego (MVP) | "Have we written down what we will do?" |
| Live assessment | "Are we doing it?" |
| Gap mitigation (Phase 5) | "When we're not, how do we fix it?" |
| Golden image (Phase 6) | "Can new systems start out compliant?" |
| Audit reports (Phase 7) | "Can we prove all of the above to an auditor?" |

The same IR feeds all five products. **One ingestion event produces
five derivative artifacts** — that's the unit-economics story behind
the customer's price point.

### 19.1 Gap mitigation (Phase 5)

Once an assessment lands a gap, the Portal can produce a remediation
artifact from the same IR + target_mapping:

| Mapping type | Output | Where it runs |
|---|---|---|
| `abstract_control × target × jinja2_remediation_role` | Ansible role / playbook | AAC AAP launches it via the Backup → Patch → Validate contract (Piece 47 in brief) |
| `abstract_control × target × llm_remediation_fallback` | LLM-generated playbook (low-confidence flag) | Same as above; customer review of generated content recommended |

The customer flow:
1. Assessment surfaces "47 systems failing CIS 5.4.1 (password length)"
2. Portal offers: "Apply remediation across all 47 systems? (review playbook first)"
3. Customer reviews the generated Ansible playbook (same diff UI as Rego review)
4. Customer approves → AAC's Piece-47 workflow runs Backup → Patch → Validate
5. Post-remediation assessment confirms the gap closed
6. Audit log captures the entire chain

New data:
- `target_mappings.remediation_template` (Jinja or LLM prompt for the playbook)
- `customer_policy_targets.remediation_storage_key`
- `policy_audit_log.action = 'remediation_executed'` with the AAP job id

### 19.2 Golden image generation (Phase 6)

The customer wants new systems to start compliant, not get patched
into compliance after deployment. The Portal generates per-target
provisioning artifacts from the IR:

| Target system | Artifact format | Engine |
|---|---|---|
| RHEL / CentOS / Rocky | Kickstart `.ks` | Jinja template + IR |
| Ubuntu / Debian | Cloud-init / autoinstall YAML | Jinja template + IR |
| Windows Server | Sysprep + Group Policy bundle | Jinja template + IR |
| AWS AMI | Packer manifest + provisioner playbook | Packer + Ansible role |
| Azure VM | Packer manifest + provisioner playbook | Packer + Ansible role |
| Container images | Containerfile / Dockerfile (with hardening directives) | Jinja template + IR |

Customer journey:
1. Customer publishes policies as in MVP
2. Customer hits "Generate golden image config" on the Portal dashboard
3. Selects target platforms (AWS AMI, Containerfile, Kickstart, etc.)
4. Portal generates provisioning artifacts; signs them; commits to a `golden_images/` directory in the tenant git repo
5. Customer's CI/CD pulls the signed artifacts, builds images, signs the resulting image
6. Image attestation lands back at the Portal with the policy version it was built against

This closes the loop: **the customer's image factory is downstream of
the Portal's policy bus.** Update a policy → next image build is
automatically aligned.

New data:
- `target_mappings.image_template` (per target_system; engine + body)
- `customer_golden_images` table: (tenant_id, target_system, policy_version_set, image_sha, attestation_signature)
- `policy_audit_log.action = 'golden_image_built'`

---

## 20. Audit-ready policy reports

This is the deliverable an auditor wants. Phase 7.

### 20.1 What goes in a report

For each enrolled framework, for a customer-chosen time range
(quarter, year, since-last-audit):

| Section | Content |
|---|---|
| **Header** | Tenant identity, framework, time range, signing key fingerprint, report generation timestamp |
| **Policy lineage** | Every active policy (published + archived during the window): name, version, effective date, owner, prose-doc link, IR hash, generated Rego shas |
| **Live posture** | Compliance % per control, per host class, with trend over the window |
| **Gap history** | Every gap detected in the window: control, hosts affected, first-seen, mitigation applied (with playbook reference + AAP job id), mitigation date, post-mitigation re-assessment result |
| **Golden image attestations** | Every image built in the window: target platform, policy version set it was built against, image sha, build attestation signature |
| **Chain of custody** | Every authorized action in the window — policy authored by, reviewed by, approved by, published by, accessed by; from `policy_audit_log` |
| **Bundle history** | Every bundle the customer's AAC pulled in the window: bundle sha, contained policy versions, pulled-at timestamp, bridge-side verification result |
| **Operator certifications** | Portal-side attestations: SOC 2 report reference (when achieved), penetration test reference, dependency SBOM, key rotation log |
| **Sign-off block** | Customer signing as accountable; Portal signing as authoritative source of policy + Rego + assessment evidence |

### 20.2 Format

Two outputs from the same data:

| Format | Use case | Generated by |
|---|---|---|
| **DOCX + signed PDF** | Hand to the auditor; printable | Per the existing `document_production.md` convention — python-docx + Chrome-headless PDF |
| **Machine-readable JSON bundle (signed)** | Auditor ingestion into their evidence platform (Drata / Vanta / etc.); chain-of-custody preserved | Direct from the database |

### 20.3 Sign-and-deliver

The report is **signed by the Portal** with an authoritative key (per
brief decision D6). Customer downloads via the operator console; can
optionally have the Portal deliver direct to an auditor's S3 bucket /
SFTP / email with a one-time link.

This is distinct from Piece 19 (audit evidence delivery — raw evidence
bundles) and Piece 26 (audit certification — signed authoritative
output). **Section 20 is the human-readable narrative layer** built on
top of Pieces 19 + 26.

### 20.4 Why this is defensible

The customer can show the auditor:

1. The written policy (uploaded prose document, immutable in object storage with SHA-256)
2. The generated Rego (signed, with provenance from IR to file)
3. The assessment results (compliance_results, with timestamps and the OPA bundle sha that evaluated them)
4. The mitigations (AAP job stdout from Backup → Patch → Validate workflows)
5. The golden image attestations (build-time policy version baked into the image manifest)
6. The chain of custody (who authored / reviewed / approved each artifact, when, with MFA-asserted identity)

That's an end-to-end story no Excel-and-screenshot audit prep can match.

---

## 21. Updated phased implementation plan

### Phase 1 — foundations (sprints 1-2)
(unchanged from §17 — tenant users, RBAC, TOTP MFA, per-tenant git, object store, audit log)

### Phase 2 — Path A end-to-end (sprints 3-4)
(unchanged — parsers, IR extractor, hybrid generator, Rego validator, frontend upload + review, publish to bucket, WebAuthn MFA)

### Phase 3 — Path B end-to-end (sprints 5-6)
(unchanged — standard library browser, fork + diff editor, overlay storage, drift detection)

### Phase 4 — bundle delivery (sprints 7-8) — **MVP complete here**
(unchanged — bundle assembler, signed delivery endpoint, AAC bridge update, soak test)

### Phase 5 — gap mitigation (sprints 9-10)
- New `target_mappings.remediation_template` populated for the starter library
- LLM-generated remediation fallback
- Frontend: "Apply remediation" action on gap-list view
- Wire into Piece 47 (Backup → Patch → Validate workflow)
- Audit log capture of remediation events

### Phase 6 — golden image generation (sprints 11-12)
- New `target_mappings.image_template` for the starter library × image format combinations
- Frontend: "Generate golden image config" action
- Sign + commit provisioning artifacts to tenant git
- Customer-side: example CI/CD pipeline that consumes the signed artifacts and produces signed images
- Build attestation ingestion endpoint
- New `customer_golden_images` table

### Phase 7 — audit reports (sprints 13-14)
- Report generator service (DOCX + PDF + signed JSON bundle)
- Frontend: "Generate audit report" with time-range picker + framework selector
- Direct-to-auditor delivery options (S3, SFTP, signed link)
- Portal-side certification artifacts ingestion (SOC 2 ref, pentest ref, SBOM)

### Total

**14 sprints / ~28 weeks** to ship the full loop. Phases 1-4 (~16 weeks) deliver an MVP that proves the architecture and onboards first customers; Phases 5-7 build the strategic moat.
