"""Tenant scoping for compliance reads.

The compliance DB doesn't carry tenant_id today, so we maintain the
mapping on the portal side via `tenant_host_mapping` (migration 015).
This module is the single helper every compliance router uses to
translate a tenant_id into "the hostnames this tenant may see".

Pattern:

    allowed = await allowed_hostnames(portal_pool, tenant_id)
    if not allowed:
        return []   # tenant has no mapped hosts → empty result
    rows = await compliance_pool.fetch(
        "SELECT ... FROM compliance_results WHERE hostname = ANY($1)",
        list(allowed),
    )

Why a Python-level filter and not a foreign data wrapper:

  - postgres_fdw works but adds operational coupling (the compliance
    DB needs to know the portal DB exists, manage user mappings,
    refresh statistics, etc.)
  - A two-query pattern is one extra round-trip on a single tenant's
    mapping (small set, indexed by tenant_id) — negligible
  - The mapping table being portal-owned means the assessment
    pipeline never has to know about tenants
"""
from __future__ import annotations

from uuid import UUID

import asyncpg


async def allowed_hostnames(
    portal_pool: asyncpg.Pool,
    tenant_id: UUID | str,
    framework: str | None = None,
) -> set[str]:
    """Return the set of hostnames this tenant may read compliance for.

    If `framework` is provided, the mapping's framework column is
    matched too: NULL rows (which mean "any framework") and rows that
    exactly match `framework` both pass. Pass framework=None to get
    the union — every hostname this tenant may see for ANY framework.
    """
    if framework is None:
        rows = await portal_pool.fetch(
            "SELECT DISTINCT hostname FROM tenant_host_mapping WHERE tenant_id = $1::uuid",
            str(tenant_id),
        )
    else:
        # A row with framework IS NULL means "all frameworks for this
        # host". A row with framework = $2 means "this framework only".
        # We want either.
        rows = await portal_pool.fetch(
            """
            SELECT DISTINCT hostname FROM tenant_host_mapping
             WHERE tenant_id = $1::uuid
               AND (framework IS NULL OR framework = $2)
            """,
            str(tenant_id),
            framework,
        )
    return {r["hostname"] for r in rows}
