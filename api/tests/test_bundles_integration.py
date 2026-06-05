"""Integration tests for the new bundle endpoints (PR 23 + 24).

Covers:
  - GET /portal/v1/me/bundles — list + cursor pagination
  - GET /portal/v1/me/bundles/{bundle_id}/manifest — detail + tenant
    isolation (no existence leak across tenants)

The list endpoint's payload is intentionally lean (bytes / envelope /
full manifest jsonb excluded); these tests pin that contract.

`require_tenant_user_mfa` is dependency-overridden so the tests can
seed a synthetic session and skip the password + TOTP dance.
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


# ── Test scaffolding ──────────────────────────────────────────────────


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
async def client_for(pg_pool):
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


async def _insert_bundle(
    pool,
    tenant_id,
    *,
    built_by,
    built_at: datetime,
    sha: str,
    target_count: int = 1,
    excluded: int = 0,
):
    """Direct INSERT — sidesteps the real bundle builder so these
    tests don't depend on `opa build` or signing-key material. The
    columns we don't assert on get harmless filler values."""
    return await pool.fetchval(
        """INSERT INTO policy_bundles
               (tenant_id, bundle_sha256, bundle_bytes, bundle_byte_size,
                signed_envelope_bytes, signing_key_id, manifest,
                target_count, customer_policy_ids,
                excluded_target_count, excluded_targets_log,
                built_at, built_by_user_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb,
                   $8, $9, $10, $11::jsonb, $12, $13)
           RETURNING id""",
        tenant_id,
        sha,
        b"\x1f\x8b\x08\x00",  # gzip magic; payload is filler
        4,
        b"sig",
        "test-key",
        json.dumps({"manifest_filler": True}),
        target_count,
        [],
        excluded,
        json.dumps([]),
        built_at,
        built_by,
    )


# ── List endpoint ─────────────────────────────────────────────────────


async def test_history_list_is_reverse_chronological_and_lean(
    pg_pool, seeded, client_for
):
    """Most recent first. Payload includes only the lean summary fields
    — no bundle_bytes, no signed_envelope_bytes, no full manifest jsonb."""
    now = datetime.now(timezone.utc)
    await _insert_bundle(
        pg_pool, seeded["tenant_a"],
        built_by=seeded["user_a"], built_at=now - timedelta(minutes=2),
        sha="a" * 64,
    )
    await _insert_bundle(
        pg_pool, seeded["tenant_a"],
        built_by=seeded["user_a"], built_at=now - timedelta(minutes=1),
        sha="b" * 64,
    )
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get("/api/portal/v1/me/bundles")
    assert r.status_code == 200
    rows = r.json()
    assert [row["bundle_sha256"] for row in rows] == ["b" * 64, "a" * 64]
    sample = rows[0]
    # Lean — none of the heavy fields are serialized.
    for forbidden in ("bundle_bytes", "signed_envelope_bytes", "manifest"):
        assert forbidden not in sample
    assert sample["built_by_email"] == "alice@a.example"


async def test_history_excludes_other_tenants(pg_pool, seeded, client_for):
    """Tenant A only sees their own bundles. Tenant B's bundles are
    invisible regardless of how many they have."""
    now = datetime.now(timezone.utc)
    await _insert_bundle(
        pg_pool, seeded["tenant_a"], built_by=seeded["user_a"],
        built_at=now, sha="a" * 64,
    )
    await _insert_bundle(
        pg_pool, seeded["tenant_b"], built_by=seeded["user_b"],
        built_at=now, sha="b" * 64,
    )
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get("/api/portal/v1/me/bundles")
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["bundle_sha256"] == "a" * 64


async def test_compound_cursor_paginates_without_overlap(
    pg_pool, seeded, client_for
):
    now = datetime.now(timezone.utc)
    for i in range(7):
        await _insert_bundle(
            pg_pool, seeded["tenant_a"], built_by=seeded["user_a"],
            built_at=now - timedelta(minutes=i),
            sha=f"{i:064x}",
        )
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r1 = await c.get("/api/portal/v1/me/bundles?limit=3")
        page1 = r1.json()
        assert len(page1) == 3
        last = page1[-1]
        r2 = await c.get(
            "/api/portal/v1/me/bundles"
            f"?limit=10&before_built_at={last['built_at']}"
            f"&before_id={last['bundle_id']}"
        )
        page2 = r2.json()
    seen = {row["bundle_id"] for row in page1} | {row["bundle_id"] for row in page2}
    assert len(seen) == 7  # no overlap; full coverage
    assert len(page2) == 4


async def test_compound_cursor_collision_safe_within_same_microsecond(
    pg_pool, seeded, client_for
):
    """Same built_at on multiple bundles — without the id tiebreaker
    we'd either duplicate or lose the boundary row. This pins the
    contract that the cursor is the (built_at, id) PAIR, not just
    the timestamp."""
    same = datetime.now(timezone.utc)
    ids = []
    for sha in ("a" * 64, "b" * 64, "c" * 64):
        ids.append(
            await _insert_bundle(
                pg_pool, seeded["tenant_a"], built_by=seeded["user_a"],
                built_at=same, sha=sha,
            )
        )
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r1 = await c.get("/api/portal/v1/me/bundles?limit=2")
        page1 = r1.json()
        last = page1[-1]
        r2 = await c.get(
            "/api/portal/v1/me/bundles"
            f"?limit=10&before_built_at={last['built_at']}"
            f"&before_id={last['bundle_id']}"
        )
        page2 = r2.json()
    seen = {row["bundle_id"] for row in page1} | {row["bundle_id"] for row in page2}
    assert seen == {str(i) for i in ids}
    assert len(seen) == 3


async def test_cursor_rejects_unpaired_params(seeded, client_for):
    """before_built_at without before_id (or vice versa) is a 400 —
    the cursor is a pair, not two independent filters. Use httpx
    `params=` so the +00:00 in the timestamp gets properly URL-encoded
    rather than letting the server interpret it as a space."""
    now = datetime.now(timezone.utc).isoformat()
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(
            "/api/portal/v1/me/bundles", params={"before_built_at": now}
        )
    assert r.status_code == 400, r.text

    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(
            "/api/portal/v1/me/bundles", params={"before_id": str(uuid4())}
        )
    assert r.status_code == 400, r.text


async def test_built_by_email_null_when_user_deleted(
    pg_pool, seeded, client_for
):
    """built_by_user_id has FK ON DELETE SET NULL; the bundle survives,
    but the join returns NULL. UI renders that as '(user removed)'."""
    now = datetime.now(timezone.utc)
    await _insert_bundle(
        pg_pool, seeded["tenant_a"], built_by=seeded["user_a"],
        built_at=now, sha="a" * 64,
    )
    async with pg_pool.acquire() as conn:
        await conn.execute("DELETE FROM tenant_users WHERE id = $1", seeded["user_a"])

    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get("/api/portal/v1/me/bundles")
    assert r.json()[0]["built_by_email"] is None


# ── Detail endpoint ───────────────────────────────────────────────────


async def test_manifest_by_id_returns_full_manifest(
    pg_pool, seeded, client_for
):
    """Detail endpoint returns the heavy manifest jsonb the list endpoint
    omits."""
    now = datetime.now(timezone.utc)
    bid = await _insert_bundle(
        pg_pool, seeded["tenant_a"], built_by=seeded["user_a"],
        built_at=now, sha="a" * 64,
    )
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(f"/api/portal/v1/me/bundles/{bid}/manifest")
    assert r.status_code == 200
    body = r.json()
    assert body["bundle_sha256"] == "a" * 64
    assert body["manifest"] == {"manifest_filler": True}
    assert "excluded_targets_log" in body


async def test_manifest_404s_on_foreign_tenant_id(
    pg_pool, seeded, client_for
):
    """A bundle id owned by another tenant 404s — identical response
    shape to a non-existent id, so existence doesn't leak across
    tenants."""
    now = datetime.now(timezone.utc)
    bid_b = await _insert_bundle(
        pg_pool, seeded["tenant_b"], built_by=seeded["user_b"],
        built_at=now, sha="b" * 64,
    )
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(f"/api/portal/v1/me/bundles/{bid_b}/manifest")
    assert r.status_code == 404


async def test_manifest_404s_on_unknown_id(seeded, client_for):
    bogus = uuid4()
    async with client_for(seeded["tenant_a"], seeded["user_a"]) as c:
        r = await c.get(f"/api/portal/v1/me/bundles/{bogus}/manifest")
    assert r.status_code == 404
