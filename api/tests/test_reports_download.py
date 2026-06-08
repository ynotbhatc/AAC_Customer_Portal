"""Real-DB tests for /api/reports/download (P1).

The router pulls from TWO pools (portal for tenant_host_mapping,
compliance for compliance_results) and dispatches to 3 different
generators. Mock tests would miss cross-pool query bugs, so we use
the testcontainers PG fixture for behavior coverage; the pure
generator functions get a separate unit-test pass.

Pins:
  - CSV: returns text/csv with comment header + data rows
  - JSON: parses; results filtered by tenant's allowed hostnames
  - PDF: returns application/pdf, starts with %PDF magic bytes
  - empty allowed set returns a valid empty report (not 404, not 403)
  - cross-tenant hostname filter returns empty report (no info leak)
  - filename includes the framework
"""
from __future__ import annotations

import csv
import io
import json
from uuid import UUID

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


# ── Scaffolding ───────────────────────────────────────────────────────


@pytest_asyncio.fixture(loop_scope="session")
async def seeded(pg_pool):
    """Two tenants + their mappings + sample compliance_results rows.

    Test uses the SAME pool for portal and compliance roles by
    creating the compliance_results table inside the portal DB.
    Production uses two separate DBs; this conflation is fine for
    behavioral testing because the router takes pools via DI and we
    override both to point at pg_pool.

    Tenant A: 1 mapped host (host-a.example), 3 results
    Tenant B: 1 mapped host (host-b.example), 1 result
    """
    # Create compliance_results in the same DB (matches the
    # production schema column-for-column). The TRUNCATE on the next
    # line resets state between tests — pg_pool's standard cleanup
    # list doesn't include compliance_results because the table
    # isn't part of any migration (it lives in a different DB in
    # production).
    async with pg_pool.acquire() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS compliance_results (
                id                    bigserial PRIMARY KEY,
                hostname              text NOT NULL,
                framework             varchar(100) NOT NULL,
                policy_name           text,
                policy_version        text,
                total_controls        int,
                passed_controls       int,
                failed_controls       int,
                compliance_percentage numeric,
                compliant             boolean,
                violations            jsonb,
                metadata              jsonb,
                evaluation_timestamp  timestamptz NOT NULL DEFAULT NOW()
            )
            """
        )
        await conn.execute("TRUNCATE compliance_results")

        ta = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant A",
        )
        tb = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant B",
        )
        ua = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'account_owner', false) RETURNING id""",
            ta, "owner@a.example",
        )
        ub = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'account_owner', false) RETURNING id""",
            tb, "owner@b.example",
        )
        await conn.execute(
            "INSERT INTO tenant_host_mapping (tenant_id, hostname) VALUES ($1, $2)",
            ta, "host-a.example",
        )
        await conn.execute(
            "INSERT INTO tenant_host_mapping (tenant_id, hostname) VALUES ($1, $2)",
            tb, "host-b.example",
        )

        # Seed 3 results for tenant A's host
        import json as _json
        for i in range(3):
            await conn.execute(
                """INSERT INTO compliance_results
                   (hostname, framework, policy_name, policy_version,
                    total_controls, passed_controls, failed_controls,
                    compliance_percentage, compliant, violations, metadata,
                    evaluation_timestamp)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb,
                           NOW() - ($12 || ' hours')::interval)""",
                "host-a.example", "cis_rhel9", "CIS RHEL 9", "v2.0.0",
                100, 90 + i, 10 - i, 90.0 + i, (i == 2),
                _json.dumps(["finding 1", "finding 2"]),
                _json.dumps({"section": str(i)}),
                str(i * 12),
            )
        # 1 result for tenant B's host
        await conn.execute(
            """INSERT INTO compliance_results
               (hostname, framework, policy_name, policy_version,
                total_controls, passed_controls, failed_controls,
                compliance_percentage, compliant, violations, metadata,
                evaluation_timestamp)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, NOW())""",
            "host-b.example", "cis_rhel9", "CIS RHEL 9", "v2.0.0",
            100, 100, 0, 100.0, True,
            _json.dumps([]),
            _json.dumps({"section": "0"}),
        )

    return {"tenant_a": ta, "tenant_b": tb, "owner_a": ua, "owner_b": ub}


@pytest_asyncio.fixture(loop_scope="session")
async def client_factory(pg_pool):
    from main import app
    from src.core.database import get_pool as get_compliance_pool_dep
    from src.core.portal_db import get_portal_pool
    from src.core.sessions import require_tenant_user

    async def _get_portal():
        return pg_pool

    async def _get_compliance():
        return pg_pool

    def _make(tenant_id: UUID, user_id: UUID, email: str = "u@example"):
        fake = {
            "session_id": UUID("11111111-1111-1111-1111-111111111111"),
            "tenant_user_id": user_id,
            "tenant_id": tenant_id,
            "email": email,
            "display_name": "u",
            "role": "account_owner",
            "mfa_required": False,
            "mfa_enrolled": False,
            "mfa_verified": True,
        }

        async def _user_dep(request=None):
            if request is not None:
                request.state.tenant_user = fake
            return fake

        app.dependency_overrides[get_portal_pool] = _get_portal
        app.dependency_overrides[get_compliance_pool_dep] = _get_compliance
        app.dependency_overrides[require_tenant_user] = _user_dep
        return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")

    yield _make
    app.dependency_overrides.clear()


# ── Format-specific assertions ───────────────────────────────────────


async def test_json_format_returns_tenant_scoped_rows(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/reports/download", params={"format": "json"})
        assert r.status_code == 200, r.text
        assert r.headers["content-type"].startswith("application/json")
        body = json.loads(r.content)
        # All 3 rows for host-a.example
        assert body["summary"]["row_count"] == 3
        assert all(row["hostname"] == "host-a.example" for row in body["results"])


async def test_csv_format_includes_header_and_rows(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/reports/download", params={"format": "csv"})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/csv")
        text = r.content.decode("utf-8")
        # CSV-comment metadata block
        assert "# AAC Compliance Report" in text
        # Header row
        assert "hostname,framework" in text
        # Skip the comment block, parse the rest as CSV
        data_block = text[text.index("hostname"):]
        reader = csv.reader(io.StringIO(data_block))
        rows = list(reader)
        # 1 header + 3 data
        assert len(rows) == 4


async def test_pdf_format_starts_with_pdf_magic(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/reports/download", params={"format": "pdf"})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("application/pdf")
        # Every PDF starts with the magic bytes "%PDF-"
        assert r.content.startswith(b"%PDF-")
        # Non-trivial size
        assert len(r.content) > 1000


# ── Tenant scoping ───────────────────────────────────────────────────


async def test_tenant_b_does_not_see_tenant_a_rows(seeded, client_factory):
    async with client_factory(seeded["tenant_b"], seeded["owner_b"]) as c:
        r = await c.get("/api/reports/download", params={"format": "json"})
        assert r.status_code == 200
        body = json.loads(r.content)
        # Only host-b.example's single row
        assert body["summary"]["row_count"] == 1
        assert body["results"][0]["hostname"] == "host-b.example"


async def test_tenant_with_no_mapped_hosts_gets_empty_report(client_factory, pg_pool):
    """Self-contained — creates its own tenant + user without
    inserting any tenant_host_mapping rows. Avoids order-dependent
    state mutations on the shared `seeded` fixture."""
    async with pg_pool.acquire() as conn:
        tc = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Tenant C (no mappings)",
        )
        uc = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'account_owner', false) RETURNING id""",
            tc, "owner@c.example",
        )

    async with client_factory(tc, uc) as c:
        r = await c.get("/api/reports/download", params={"format": "json"})
        assert r.status_code == 200
        body = json.loads(r.content)
        assert body["summary"]["row_count"] == 0
        assert body["results"] == []


async def test_hostname_filter_outside_allowed_returns_empty(seeded, client_factory):
    # Tenant A asking for tenant B's host
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get(
            "/api/reports/download",
            params={"format": "json", "hostname": "host-b.example"},
        )
        assert r.status_code == 200
        body = json.loads(r.content)
        assert body["summary"]["row_count"] == 0


# ── Filename ─────────────────────────────────────────────────────────


async def test_filename_includes_framework(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get(
            "/api/reports/download",
            params={"format": "csv", "framework": "cis_rhel9"},
        )
        assert r.status_code == 200
        cd = r.headers["content-disposition"]
        assert 'filename="aac-report-cis_rhel9.csv"' in cd


async def test_filename_defaults_to_all_when_no_framework_filter(seeded, client_factory):
    async with client_factory(seeded["tenant_a"], seeded["owner_a"]) as c:
        r = await c.get("/api/reports/download", params={"format": "pdf"})
        cd = r.headers["content-disposition"]
        assert 'filename="aac-report-all.pdf"' in cd
