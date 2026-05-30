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
