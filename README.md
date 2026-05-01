# AAC Customer Portal

Customer-facing web portal for **Ansible Automated Compliance (AAC)**.
Provides compliance dashboards, historical trending, report downloads,
and remediation tracking — all backed by the AAC PostgreSQL `compliance_results`
table and OPA policy evaluation.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Customer Portal                      │
│                                                       │
│   frontend/        React + Vite + Tailwind CSS        │
│   api/             FastAPI (Python 3.11)              │
└──────────────┬──────────────────┬────────────────────┘
               │                  │
               ▼                  ▼
   PostgreSQL (compliance)    OPA (:8181–8183)
   compliance_results table   Policy evaluation
               │
               ▼
   Ansible Automation Platform
   (job template launches)
```

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, Tailwind CSS, Recharts |
| API | FastAPI (Python 3.11), asyncpg, httpx |
| Auth | AAP OAuth2 / session tokens |
| Database | PostgreSQL 15 (AAC `compliance` DB, read-only) |
| Deploy | Podman Compose (dev) / OpenShift (prod) |

## Repository Structure

```
frontend/          # React application
  src/
    components/    # UI components (dashboard, reports, remediation, common)
    pages/         # Route-level pages
    hooks/         # Custom React hooks
    lib/           # API client, utilities
    types/         # TypeScript interfaces

api/               # FastAPI backend
  src/
    routers/       # Route handlers (compliance, reports, remediation, auth)
    models/        # Pydantic models
    services/      # Database + OPA service layer
    core/          # Config, database pool, auth

deploy/            # Deployment manifests
  openshift/       # OpenShift / OCP manifests
  podman/          # Podman Compose for local/EC2 dev
  scripts/         # Deploy helper scripts

docs/              # Architecture, API reference, runbooks
```

## Quick Start (local dev)

```bash
# 1. Configure environment
cp deploy/podman/env.example .env
# edit .env: set PG_HOST, PG_PASSWORD, AAP_URL, AAP_TOKEN

# 2. Start all services
podman-compose -f deploy/podman/docker-compose.yml up -d

# 3. Open portal
open http://localhost:3000
```

## Data Source

All compliance data is read-only from the AAC PostgreSQL `compliance_results` table:

```sql
SELECT hostname, framework, policy_name, compliance_percentage,
       compliant, violations, evaluation_timestamp
FROM compliance_results
ORDER BY evaluation_timestamp DESC;
```

No writes to the compliance database — the portal is a read-only view layer.

## Deployment

### Podman (EC2 demo host)
```bash
cd deploy/podman
podman-compose up -d
```

### OpenShift
```bash
oc apply -f deploy/openshift/
```

## Connection to AAC

The portal connects to the same infrastructure as the AAC demo host:

| Service | Default |
|---------|---------|
| PostgreSQL | `$PG_HOST:5432/compliance` (read-only `compliance_reader` user) |
| OPA Security | `http://$AAP_HOST:8181` |
| OPA Compliance | `http://$AAP_HOST:8182` |
| OPA OT | `http://$AAP_HOST:8183` |
| AAP Controller | `https://$AAP_HOST` |
