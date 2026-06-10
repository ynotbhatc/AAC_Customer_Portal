"""Pin the AuditMiddleware resource tagging for tenant + tenant_token
write endpoints.

Bridge token issuance lands in `system_audit_log` via the audit
middleware (POST is in AUDITED_METHODS). Before this PR the tenant
router didn't set `request.state.audit_resource`, so the row had
`resource_type` and `resource_id` NULL — auditors couldn't slice the
log by "every tenant_token issuance event" without grepping path
strings, which is brittle (path schemes change).

These tests stub out `AuditMiddleware._write_audit` so we can
inspect exactly what the router-attached state.audit_resource looks
like by the time the middleware sees the response. We don't need a
real DB to verify that contract — the persistence path is already
covered by test_audit_actor.py and test_audit_log.py.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request
from starlette.responses import Response


pytestmark = [
    pytest.mark.integration,
    pytest.mark.asyncio(loop_scope="session"),
]


ADMIN = {"Authorization": "Bearer test-admin-token"}


@pytest_asyncio.fixture(loop_scope="session")
async def captured(pg_pool):
    """Mount the real app, monkeypatch AuditMiddleware._write_audit
    to capture what request.state holds, and yield a client + the
    captured list."""
    from main import app
    from src.core.audit_middleware import AuditMiddleware
    from src.core.portal_db import get_portal_pool

    rows: list[dict] = []
    original_write_audit = AuditMiddleware._write_audit

    async def _capture(self, request: Request, status_code: int) -> None:
        resource = getattr(request.state, "audit_resource", (None, None))
        rows.append({
            "method": request.method,
            "path": request.url.path,
            "status_code": status_code,
            "resource_type": resource[0],
            "resource_id": str(resource[1]) if resource[1] is not None else None,
        })

    AuditMiddleware._write_audit = _capture

    async def _get_pool():
        return pg_pool

    app.dependency_overrides[get_portal_pool] = _get_pool

    # Seed: one tenant + one token so PATCH / DELETE / revoke have
    # real targets and the router's existence checks pass.
    async with pg_pool.acquire() as conn:
        tenant_id = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "Audit Resource Test Tenant",
        )
        token_row = await conn.fetchrow(
            """
            INSERT INTO tenant_tokens
                (tenant_id, token_id, token_secret_hash,
                 token_secret_plaintext, description, scopes)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING token_id
            """,
            tenant_id,
            "aac_pretest_existing0001",
            "$2b$04$abcdefghijklmnopqrstuv.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "plaintext-secret-stub",
            "pre-existing token for revoke test",
            ["read"],
        )

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield {
                "client": c,
                "rows": rows,
                "tenant_id": str(tenant_id),
                "existing_token_id": token_row["token_id"],
            }
    finally:
        app.dependency_overrides.clear()
        AuditMiddleware._write_audit = original_write_audit


def _find(rows, **wanted):
    for r in rows:
        if all(r.get(k) == v for k, v in wanted.items()):
            return r
    return None


async def test_create_token_tags_resource(captured):
    r = await captured["client"].post(
        f"/api/admin/v1/tenants/{captured['tenant_id']}/tokens",
        headers=ADMIN,
        json={"description": "bridge token for audit test", "scopes": ["read"]},
    )
    assert r.status_code == 201, r.text
    token_id = r.json()["token_id"]

    row = _find(captured["rows"], method="POST", resource_id=token_id)
    assert row is not None, (
        f"no audit row tagged with the new token_id; got: {captured['rows']}"
    )
    assert row["resource_type"] == "tenant_token", row
    assert row["status_code"] == 201, row
    assert row["path"].endswith("/tokens"), row


async def test_revoke_token_tags_resource(captured):
    r = await captured["client"].post(
        f"/api/admin/v1/tenants/{captured['tenant_id']}/tokens/"
        f"{captured['existing_token_id']}/revoke",
        headers=ADMIN,
        json={"reason": "audit test revocation"},
    )
    assert r.status_code == 204, r.text

    row = _find(
        captured["rows"],
        method="POST",
        resource_id=captured["existing_token_id"],
    )
    assert row is not None, "no audit row for revoke_token"
    assert row["resource_type"] == "tenant_token", row
    assert row["path"].endswith("/revoke"), row


async def test_create_tenant_tags_resource(captured):
    r = await captured["client"].post(
        "/api/admin/v1/tenants",
        headers=ADMIN,
        json={
            "display_name": "Created During Audit Test",
            "tier": "free",
        },
    )
    assert r.status_code == 201, r.text
    new_id = r.json()["id"]

    row = _find(captured["rows"], method="POST", resource_id=new_id)
    assert row is not None, "no audit row for create_tenant"
    assert row["resource_type"] == "tenant", row
    assert row["path"] == "/api/admin/v1/tenants", row


async def test_update_tenant_tags_resource(captured):
    r = await captured["client"].patch(
        f"/api/admin/v1/tenants/{captured['tenant_id']}",
        headers=ADMIN,
        json={"notes": "updated via audit test"},
    )
    assert r.status_code == 200, r.text

    row = _find(
        captured["rows"],
        method="PATCH",
        resource_id=captured["tenant_id"],
    )
    assert row is not None, "no audit row for update_tenant"
    assert row["resource_type"] == "tenant", row


async def test_delete_tenant_tags_resource(captured, pg_pool):
    # Soft-delete a fresh tenant so we don't affect the shared one
    # the rest of the suite uses.
    async with pg_pool.acquire() as conn:
        tid = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1, 'active') RETURNING id",
            "To Be Deleted",
        )
    r = await captured["client"].delete(
        f"/api/admin/v1/tenants/{tid}",
        headers=ADMIN,
    )
    assert r.status_code == 204, r.text

    row = _find(captured["rows"], method="DELETE", resource_id=str(tid))
    assert row is not None, "no audit row for delete_tenant"
    assert row["resource_type"] == "tenant", row
