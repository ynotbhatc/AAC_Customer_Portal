# AAC Customer Portal — Architecture

## Overview

The portal is a **read-only view layer** over the AAC compliance database.
It never writes to `compliance_results` — all data flows from AAP → OPA → PostgreSQL
via the existing AAC automation pipelines.

## Data Flow

```
AAP job templates
  └─ Collect facts (Ansible)
  └─ Evaluate via OPA (:8181/:8182/:8183)
  └─ Store to PostgreSQL compliance_results table
                    │
                    ▼
         AAC Customer Portal
         ┌────────────────────┐
         │  FastAPI (port 8000)│  ← reads compliance_results (read-only)
         │  asyncpg pool       │
         └────────┬───────────┘
                  │ JSON
         ┌────────▼───────────┐
         │  React (port 3000)  │  ← dashboards, trends, reports
         └────────────────────┘
```

## Pages

| Route | Description |
|-------|-------------|
| `/` | Executive dashboard — framework overview, top violations |
| `/hosts` | Per-host compliance status across all frameworks |
| `/frameworks/:id` | Framework detail — trend chart, control breakdown |
| `/remediation` | Open violations with status tracking |
| `/reports` | Download PDF/CSV reports |
| `/settings` | Portal configuration |

## Database Access

The API connects as the **`compliance_reader`** PostgreSQL role (read-only).
This role is created by `AAC - Initialize PostgreSQL Database` (template 114).

```sql
-- compliance_reader has SELECT only
GRANT SELECT ON compliance_results TO compliance_reader;
GRANT SELECT ON remediation_tracking TO compliance_reader;
```

## Authentication

Phase 1: No auth (internal demo use)
Phase 2: AAP OAuth2 — users log in with their AAP credentials; role-based
         access matches AAP org membership

## Deployment Targets

| Environment | Method | URL pattern |
|-------------|--------|-------------|
| Local dev | `podman-compose` | `http://localhost:3000` |
| EC2 demo host | `podman-compose` | `http://<EC2_IP>:3000` |
| OpenShift (RHPDS) | OCP manifests | `https://portal-aap.apps.<cluster>` |
