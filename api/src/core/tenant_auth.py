"""
Per-tenant Bearer auth for the customer-facing portal feed API.

Verifies `Authorization: Bearer <token_secret>` against the bcrypt hash
stored in `tenant_tokens.token_secret_hash`. The optional `X-Token-Id`
header lets the caller assert which token_id they think they're using
(helps catch stale-on-the-AAC-side rotations early).

Side effects on success:
  - tenant_tokens.last_used_at      = now()
  - tenant_tokens.last_used_from_ip = request client IP
"""
from __future__ import annotations

import asyncio
from typing import Annotated, Any
from uuid import UUID

import asyncpg
import bcrypt
from fastapi import Depends, Header, HTTPException, Request

from .portal_db import get_portal_pool


REQUIRED_SCOPE = "cve_feed"

# Tokens used by the AAC bridge to pull customer policy bundles.
# Granted via the operator-admin "AAC - Issue Bundle Pull Token" flow.
BUNDLE_PULL_SCOPE = "policy_bundle_pull"

# Tokens used by the AAC bridge to POST OPA evaluation results as
# baseline snapshots. Distinct scope so an operator can issue a
# narrower token that pulls bundles but doesn't write back, or vice
# versa, even though the typical primary-bridge token holds both.
BASELINE_PUSH_SCOPE = "baseline_push"


def require_tenant_with_scope(scope: str):
    """Dependency factory — produces a `require_tenant`-shaped dependency
    that asserts the token grants `scope` rather than the hardcoded
    `cve_feed` default. Routers consume it via `Depends(require_tenant_with_scope("policy_bundle_pull"))`.

    The MVP build keeps the original `require_tenant` for the CVE feed
    path (no breaking change to migration 001 callers) and adds this
    factory so the bundle endpoints declare their scope explicitly.
    """

    async def _checker(
        request: Request,
        tenant_id: str,
        authorization: Annotated[str | None, Header()] = None,
        x_token_id: Annotated[str | None, Header(alias="X-Token-Id")] = None,
        pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)] = None,  # type: ignore[assignment]
    ) -> dict[str, Any]:
        return await _resolve(
            request, tenant_id, authorization, x_token_id, pool, scope
        )

    return _checker


async def _verify_bcrypt(token: str, hashed: str) -> bool:
    # bcrypt.checkpw is CPU-bound but cheap (~50ms); offload to thread to
    # keep the event loop responsive under concurrent polling.
    return await asyncio.to_thread(
        bcrypt.checkpw, token.encode("utf-8"), hashed.encode("utf-8")
    )


async def _client_ip(request: Request) -> str | None:
    # Trust X-Forwarded-For only if explicitly set (deployment may put a
    # reverse proxy in front). Fall back to the socket peer.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


async def _resolve(
    request: Request,
    tenant_id: str,
    authorization: str | None,
    x_token_id: str | None,
    pool: asyncpg.Pool,
    scope: str,
) -> dict[str, Any]:
    """Shared body for require_tenant / require_tenant_with_scope.
    Scope is checked against tenant_tokens.scopes via PostgreSQL ANY().
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="empty bearer token")

    try:
        tenant_uuid = UUID(tenant_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid tenant_id")

    rows = await pool.fetch(
        """
        SELECT tt.id, tt.token_id, tt.token_secret_hash, tt.scopes,
               t.id AS tenant_id, t.display_name, t.status
          FROM tenant_tokens tt
          JOIN tenants t ON t.id = tt.tenant_id
         WHERE tt.tenant_id = $1
           AND tt.revoked_at IS NULL
           AND $2 = ANY(tt.scopes)
        """,
        tenant_uuid,
        scope,
    )
    if not rows:
        raise HTTPException(
            status_code=401, detail=f"no active {scope} token for tenant"
        )

    matched: asyncpg.Record | None = None
    for r in rows:
        if x_token_id and r["token_id"] != x_token_id:
            continue
        if await _verify_bcrypt(token, r["token_secret_hash"]):
            matched = r
            break

    if matched is None:
        raise HTTPException(status_code=401, detail="invalid bearer token")
    if matched["status"] != "active":
        raise HTTPException(status_code=403, detail=f"tenant status={matched['status']}")

    # Best-effort last-used stamp; never block the request on this.
    ip = await _client_ip(request)
    try:
        await pool.execute(
            """
            UPDATE tenant_tokens
               SET last_used_at      = now(),
                   last_used_from_ip = $1::inet
             WHERE id = $2
            """,
            ip,
            matched["id"],
        )
    except Exception:
        pass

    return {
        "tenant_id": matched["tenant_id"],
        "tenant_display_name": matched["display_name"],
        "token_id": matched["token_id"],
        "token_pk": matched["id"],
        "scopes": list(matched["scopes"] or []),
    }


async def require_tenant(
    request: Request,
    tenant_id: str,
    authorization: Annotated[str | None, Header()] = None,
    x_token_id: Annotated[str | None, Header(alias="X-Token-Id")] = None,
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)] = None,  # type: ignore[assignment]
) -> dict[str, Any]:
    """FastAPI dependency for the CVE feed pull path (scope=cve_feed).

    Preserved for migration 001 / CVE intelligence callers. New code
    that needs a different scope (e.g. policy_bundle_pull) should use
    require_tenant_with_scope instead.
    """
    return await _resolve(request, tenant_id, authorization, x_token_id, pool, REQUIRED_SCOPE)
