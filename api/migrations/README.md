# Portal-side database migrations

Schemas in this directory are for the operator's own `aac_portal`
PostgreSQL database — distinct from any customer's `compliance` database.

## Bootstrap

```bash
# As the postgres superuser, create the database + app role
sudo -u postgres psql <<'EOF'
CREATE ROLE aac_portal_app LOGIN PASSWORD 'change-me-portal';
CREATE DATABASE aac_portal OWNER aac_portal_app;
EOF

# Apply migrations in order
PGPASSWORD=change-me-portal psql \
  -h localhost -U aac_portal_app -d aac_portal \
  -f 001_cve_intelligence.sql
```

## Migration order

1. `001_cve_intelligence.sql` — tenants, tenant_tokens, tenant_inventory_catalog, tenant_pull_runs
2. `002_cve_feeds.sql` — cve_events, cve_references, feed_runs
3. `003_classification.sql` — buckets, vendors, bucket_vendor_links, cve_bucket_tags, cve_vendor_tags
4. `003a_taxonomy_seed.sql` — initial bucket + vendor taxonomy (idempotent, safe to re-run after edits)
5. `004_matching.sql` — tenant_enrollments, tenant_vendor_subscriptions, tenant_filter_preferences, tenant_cve_matches, match_runs + ALTER tenant_tokens ADD token_secret_plaintext
6. `005_cve_feed_api.sql` — cve_vendor_remediations (populated by future PSIRT adapters; v1 empty, schema present so feed router can join)
7. `006_policy_ingestion.sql` — tenant_users, tenant_user_mfa_factors, customer_policies, customer_policy_targets, abstract_controls, target_mappings, policy_audit_log. Schema foundation for the customer policy ingestion feature (Piece 46 / task #46) — see `docs/policy_ingestion_design.md`. Enables the `citext` extension. Adds Tier 1 governance columns on `customer_policies` (control owner, review cadence) that are populated in Phase 7+; MVP code paths ignore them.
8. `007_tenant_user_sessions.sql` — tenant_user_sessions, tenant_user_password_resets. Backs self-service login (`POST /api/portal/v1/auth/login`), session-based bearer auth, password reset via operator-issued one-time tokens, and force-logout. Sessions are server-side rows with bcrypt-hashed tokens; no JWTs to manage.
9. `008_policy_uploads.sql` — policy_uploads. Raw bytes + extracted plaintext per uploaded prose policy document; backs `POST /api/portal/v1/me/policies/upload`. MVP store inside the portal DB; future tiers can swap the implementation transparently — `customer_policies.source_file_storage_key` is an opaque key (no FK to this table, on purpose, per design §2).
10. `009_abstract_controls_seed.sql` — Phase 2 starter library of 10 abstract controls (password_complexity, password_rotation, account_lockout, mfa_enforcement, session_timeout, ssh_hardening, audit_log_retention, audit_log_protection, encryption_at_rest, network_segmentation) across 4 domains. Drives the closed-enum prompt in the LLM IR extractor (PR 6) and is the binding target for the hybrid Rego generator (PR 7). `ON CONFLICT DO NOTHING`, so adding custom rows by hand is safe across re-runs.
11. `010_target_mappings_password_complexity.sql` — schema tweak (relaxes `target_mappings.template_body` to nullable, adds a `template_ref` column, enforces "exactly one source" via CHECK) + seeds 4 mappings for `password_complexity × {linux, windows, kubernetes, network_device}`. Templates live as tracked files under `api/src/policy_ingestion/templates/`. The remaining 9 controls × 4 targets are PR 8 — purely additive content.
12. `011_target_mappings_batch_2.sql` — adds 8 more target_mappings rows: `session_timeout × {linux, windows, kubernetes, network_device}` + `audit_log_retention × {linux, windows, kubernetes, network_device}`. All 8 templates render + pass `opa check --v1-compatible` locally; `session_timeout/linux` round-trip-validated against the live RHPDS opa-security cluster.
13. `012_publish_and_bundles.sql` — closes the Path A loop: adds `customer_policies.published_at` + `.published_by`, an immutability trigger that rejects in-place edits of published policies, and a new `policy_bundles` table (bytea bundle bytes + ed25519-signed envelope + jsonb manifest + history). Backs `POST /api/portal/v1/me/policies/{id}/publish`, `POST /api/portal/v1/me/bundles/build`, and the bridge-facing `GET /api/portal/v1/tenants/{tid}/bundles/{current,sha}` endpoints with scope `policy_bundle_pull`.
14. `017_audit_immutability_triggers.sql` — append-only enforcement on `policy_audit_log` and `baseline_snapshots`. BEFORE UPDATE / BEFORE DELETE triggers RAISE EXCEPTION, with ONE narrow exception: an UPDATE that only NULLs out a nullable FK column (`tenant_user_id` / `customer_policy_id` / `captured_by_user_id`) is permitted, because those FKs are `ON DELETE SET NULL` and their cascade fires legitimate UPDATEs when a referenced row is hard-deleted. SOC-2 prep: the audit trail is now tamper-evident at the storage layer. Recovery from bad data requires DROP TRIGGER → fix → CREATE TRIGGER, which itself produces a system_audit_log entry naming the operator.

PR 10 adds NO new migration — Path B reuses `customer_policies` (with `policy_source='forked_overlay'`, `parent_standard_ref`, `parent_standard_version` from migration 006) and `customer_policy_targets`.

⚠ 004 adds a `token_secret_plaintext` column on `tenant_tokens` so the
portal can authenticate outbound calls to each tenant's AAC bridge. For
v1 it's stored plaintext; production deployments must wrap with Fernet
or KMS encryption-at-rest.

## Feed adapters

After 002 is applied, kick the adapters:

```bash
# Optional: NVD API key (raises rate limit from 5 to 50 req / 30s)
export NVD_API_KEY=<your-key>

# Standalone:
PORTAL_PG_HOST=localhost \
PORTAL_PG_PASSWORD=change-me-portal \
python -m src.feeds.runner nvd --lookback-days 2

PORTAL_PG_PASSWORD=change-me-portal \
python -m src.feeds.runner cisa_kev

# Or both:
python -m src.feeds.runner all

# Or via the API (requires PORTAL_ADMIN_TOKEN):
curl -X POST -H "Authorization: Bearer $PORTAL_ADMIN_TOKEN" \
  "http://localhost:8000/api/admin/v1/feeds/nvd/run?lookback_days=7"
```

## First tenant

After migrations, use the bootstrap CLI to create the first tenant +
initial token (the admin UI requires PORTAL_ADMIN_TOKEN, which itself
requires you to have onboarded at least one operator — chicken/egg, so
the CLI exists for the first time):

```bash
PORTAL_PG_HOST=localhost \
PORTAL_PG_DATABASE=aac_portal \
PORTAL_PG_USER=aac_portal_app \
PORTAL_PG_PASSWORD=change-me-portal \
python scripts/create_tenant.py "Acme Energy" \
  --tier premium \
  --email security@acme.com \
  --aac-bridge-url https://aac.acme.com:8005
```

The token_secret is printed exactly once. Save it before closing the
terminal.
