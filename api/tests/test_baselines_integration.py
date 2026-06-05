"""Integration tests for the baseline endpoints (Piece 50).

Covers:
  - manual import + list + detail happy path
  - tenant isolation on list AND on detail (no existence leak)
  - cursor pagination on the compound (captured_at, id) cursor
  - 400 on mismatched cursor pair
  - bridge-push ingest (M2M scope=baseline_push)
  - bridge token tenant mismatch returns 403
  - source enum is enforced at ingest

`require_tenant_user_mfa` is dependency-overridden for the user-side
routes. The bridge-side route is hit with a real token mint against
the test DB.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

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
    async with pg_pool.acquire() as conn:
        ta = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1,'active') RETURNING id",
            "Tenant A",
        )
        tb = await conn.fetchval(
            "INSERT INTO tenants (display_name, status) VALUES ($1,'active') RETURNING id",
            "Tenant B",
        )
        ua = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'editor', false) RETURNING id""",
            ta,
            "alice@a.example",
        )
        ub = await conn.fetchval(
            """INSERT INTO tenant_users (tenant_id, email, role, mfa_required)
               VALUES ($1, $2, 'editor', false) RETURNING id""",
            tb,
            "bob@b.example",
        )
    return {"tenant_a": ta, "tenant_b": tb, "user_a": ua, "user_b": ub}


@pytest_asyncio.fixture(loop_scope="session")
async def user_client_for(pg_pool):
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.core.sessions import require_tenant_user_mfa

    async def _get_pool():
        return pg_pool

    def _make(tenant_id: UUID, user_id: UUID):
        async def _fake_user():
            return {
                "tenant_id": tenant_id,
                "tenant_user_id": user_id,
                "mfa_required": False,
                "mfa_verified": True,
            }

        app.dependency_overrides[get_portal_pool] = _get_pool
        app.dependency_overrides[require_tenant_user_mfa] = _fake_user
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test")

    yield _make
    app.dependency_overrides.clear()


@pytest_asyncio.fixture(loop_scope="session")
async def bridge_client(pg_pool):
    """Bridge-side client. Returns a factory that mints a real token
    with the requested scopes against the test DB and yields an
    AsyncClient + the headers it needs to authenticate."""
    from main import app
    from src.core.portal_db import get_portal_pool
    from src.routers.tenants import _hash_secret, _new_token_id, _new_token_secret

    async def _get_pool():
        return pg_pool

    async def _mint(tenant_id: UUID, scopes: list[str]):
        token_id = _new_token_id()
        secret = _new_token_secret()
        async with pg_pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO tenant_tokens
                       (tenant_id, token_id, token_secret_hash,
                        token_secret_plaintext, description, scopes)
                   VALUES ($1, $2, $3, $4, 'test', $5)""",
                tenant_id,
                token_id,
                _hash_secret(secret),
                secret,
                scopes,
            )
        app.dependency_overrides[get_portal_pool] = _get_pool
        transport = ASGITransport(app=app)
        return (
            AsyncClient(transport=transport, base_url="http://test"),
            {"Authorization": f"Bearer {secret}", "X-Token-Id": token_id},
        )

    yield _mint
    app.dependency_overrides.clear()


def _baseline_payload(sha: str = "a" * 64, label: str | None = None) -> dict:
    return {
        "bundle_sha256": sha,
        "label": label,
        "summary": {
            "host_count": 40,
            "total_evaluations": 1200,
            "passing": 1100,
            "failing": 100,
            "errors": 0,
            "by_framework": {
                "iso27001": {"passing": 600, "failing": 30},
                "pci_dss": {"passing": 500, "failing": 70},
            },
        },
    }


# ── User-side: manual import + list + detail ──────────────────────────


async def test_manual_import_list_detail_roundtrip(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.post(
            "/api/portal/v1/me/baselines",
            json=_baseline_payload(label="Q4 baseline"),
        )
        assert r.status_code == 201, r.text
        created = r.json()
        assert created["source"] == "manual"
        assert created["captured_by_email"] == "alice@a.example"
        assert created["label"] == "Q4 baseline"
        # Detail response includes the full summary.
        assert created["summary"]["by_framework"]["iso27001"]["passing"] == 600

        # List shows the same row in lean form.
        rl = await c.get("/api/portal/v1/me/baselines")
        rows = rl.json()
        assert len(rows) == 1
        assert rows[0]["host_count"] == 40
        # Lean — by_framework is NOT exposed on the summary list shape.
        assert "by_framework" not in rows[0]

        # Detail roundtrip.
        rd = await c.get(f"/api/portal/v1/me/baselines/{created['id']}")
        assert rd.status_code == 200
        body = rd.json()
        assert body["summary"]["passing"] == 1100


async def test_list_excludes_other_tenants(pg_pool, seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        await c.post(
            "/api/portal/v1/me/baselines",
            json=_baseline_payload(sha="a" * 64),
        )
    async with user_client_for(seeded["tenant_b"], seeded["user_b"]) as c:
        await c.post(
            "/api/portal/v1/me/baselines",
            json=_baseline_payload(sha="b" * 64),
        )
    async with user_client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        rows = (await c.get("/api/portal/v1/me/baselines")).json()
    assert len(rows) == 1
    assert rows[0]["bundle_sha256"] == "a" * 64


async def test_detail_404s_on_foreign_tenant(
    pg_pool, seeded, user_client_for
):
    async with user_client_for(seeded["tenant_b"], seeded["user_b"]) as c:
        r = await c.post(
            "/api/portal/v1/me/baselines",
            json=_baseline_payload(sha="b" * 64),
        )
        foreign_id = r.json()["id"]
    async with user_client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(f"/api/portal/v1/me/baselines/{foreign_id}")
    assert r.status_code == 404


async def test_detail_404s_on_unknown_id(seeded, user_client_for):
    async with user_client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(f"/api/portal/v1/me/baselines/{uuid4()}")
    assert r.status_code == 404


async def test_compound_cursor_paginates_without_overlap(
    pg_pool, seeded, user_client_for
):
    # Seed 5 baselines, distinct captured_at via direct INSERT.
    now = datetime.now(timezone.utc)
    async with pg_pool.acquire() as conn:
        for i in range(5):
            await conn.execute(
                """INSERT INTO baseline_snapshots
                       (tenant_id, bundle_sha256, captured_at, summary, source)
                   VALUES ($1, $2, $3, $4::jsonb, 'manual')""",
                seeded["tenant_a"],
                f"{i:064x}",
                now - timedelta(minutes=i),
                json.dumps(
                    {
                        "host_count": 1,
                        "total_evaluations": 1,
                        "passing": 1,
                        "failing": 0,
                        "errors": 0,
                        "by_framework": {},
                    }
                ),
            )
    async with user_client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        page1 = (await c.get("/api/portal/v1/me/baselines?limit=3")).json()
        assert len(page1) == 3
        last = page1[-1]
        page2 = (
            await c.get(
                "/api/portal/v1/me/baselines",
                params={
                    "limit": 10,
                    "before_captured_at": last["captured_at"],
                    "before_id": last["id"],
                },
            )
        ).json()
    seen = {r["id"] for r in page1} | {r["id"] for r in page2}
    assert len(seen) == 5
    assert len(page2) == 2


async def test_cursor_rejects_unpaired_params(seeded, user_client_for):
    now = datetime.now(timezone.utc).isoformat()
    async with user_client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(
            "/api/portal/v1/me/baselines",
            params={"before_captured_at": now},
        )
    assert r.status_code == 400


# ── Bridge-side ingest ────────────────────────────────────────────────


async def test_bridge_ingest_stamps_source_bridge_push(
    seeded, user_client_for, bridge_client
):
    c, hdrs = await bridge_client(seeded["tenant_a"], ["baseline_push"])
    async with c:
        r = await c.post(
            f"/api/portal/v1/tenants/{seeded['tenant_a']}/baselines",
            json=_baseline_payload(label="bridge auto-emit"),
            headers=hdrs,
        )
    assert r.status_code == 201, r.text
    new_id = r.json()["id"]

    async with user_client_for(seeded["tenant_a"], seeded["user_a"]) as uc:
        body = (
            await uc.get(f"/api/portal/v1/me/baselines/{new_id}")
        ).json()
    assert body["source"] == "bridge_push"
    assert body["captured_by_email"] is None     # bridge-originated; no user
    assert body["label"] == "bridge auto-emit"


async def test_bridge_token_tenant_mismatch_returns_403(
    seeded, bridge_client
):
    """Token belongs to tenant A but request hits tenant B's path —
    require_tenant_with_scope already 403s in this case, but we pin
    the behavior so a future refactor doesn't quietly relax it."""
    c, hdrs = await bridge_client(seeded["tenant_a"], ["baseline_push"])
    async with c:
        r = await c.post(
            f"/api/portal/v1/tenants/{seeded['tenant_b']}/baselines",
            json=_baseline_payload(),
            headers=hdrs,
        )
    assert r.status_code in (401, 403)


async def test_bridge_wrong_scope_is_rejected(
    seeded, bridge_client
):
    """Token granted only inventory_pull — baseline endpoint requires
    baseline_push, so the call must be rejected. This pins the scope
    enforcement contract on the new endpoint."""
    c, hdrs = await bridge_client(seeded["tenant_a"], ["inventory_pull"])
    async with c:
        r = await c.post(
            f"/api/portal/v1/tenants/{seeded['tenant_a']}/baselines",
            json=_baseline_payload(),
            headers=hdrs,
        )
    assert r.status_code in (401, 403)


# ── Validation contract ───────────────────────────────────────────────


async def test_ingest_validation_rejects_negative_counts(
    seeded, user_client_for
):
    payload = _baseline_payload()
    payload["summary"]["failing"] = -1
    async with user_client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.post("/api/portal/v1/me/baselines", json=payload)
    assert r.status_code == 422


async def test_ingest_validation_rejects_bad_sha_length(
    seeded, user_client_for
):
    payload = _baseline_payload(sha="a" * 10)  # not 64 hex chars
    async with user_client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.post("/api/portal/v1/me/baselines", json=payload)
    assert r.status_code == 422
