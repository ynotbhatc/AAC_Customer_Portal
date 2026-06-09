"""Tenant-facing permission audit surface.

Closes docs/security_roadmap.md "Permission audit reporting": tenant
users should be able to see who has what role inside their own
tenant, without needing operator access. This is the read-only
companion to the operator's tenant_users admin surface.

Two payloads in one endpoint:

- `users`: every active row in this tenant's `tenant_users`, with the
  caller flagged via `self=true` so the UI can highlight their row.
- `roles`: a static capability matrix describing what each role can
  do. Lives in code (not in the DB) because it's an authoritative
  description of the codebase's enforcement, not a per-tenant
  setting.

Auth: any logged-in tenant user (viewer or higher). This is read-
only metadata about the tenant's own membership, so we don't gate
it behind editor / account_owner — but the response is still
strictly tenant-scoped via the session's `tenant_id`.
"""
from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from ..core.portal_db import get_portal_pool
from ..core.sessions import require_tenant_user


router = APIRouter(
    prefix="/portal/v1/me/permissions",
    tags=["portal:permissions"],
    dependencies=[Depends(require_tenant_user)],
)


# ── Models ───────────────────────────────────────────────────────────


class PermissionUser(BaseModel):
    """One row in the tenant's user roster.

    `self_` aliases to `self` on the wire — `self` is a Python
    keyword in many serialization contexts, so the field name stays
    suffixed in Python while the JSON shape matches what the
    frontend reads.
    """

    model_config = ConfigDict(populate_by_name=True)

    tenant_user_id: UUID
    email: str
    display_name: str | None
    role: str
    self_: bool = Field(alias="self", serialization_alias="self")


class RoleCapability(BaseModel):
    """Static capability description for one role."""

    name: str
    description: str
    capabilities: list[str]


class PermissionsResponse(BaseModel):
    users: list[PermissionUser]
    roles: list[RoleCapability]


# ── Static role catalog ──────────────────────────────────────────────


# Mirrors src/core/rbac.py Role enum + the editor/account_owner gates
# wired in PR #63. If a new role is added or capabilities shift, this
# matrix is the single place to keep in sync — see
# `test_permissions.py::test_capabilities_mention_every_gated_router`.
_ROLE_CATALOG: list[RoleCapability] = [
    RoleCapability(
        name="viewer",
        description="Read-only access to this tenant's policies, baselines, "
        "bundles, remediation items, and audit logs.",
        capabilities=[
            "Read policies, baselines, bundles, and audit logs",
            "Read remediation items and history",
        ],
    ),
    RoleCapability(
        name="editor",
        description="Everything a viewer can do, plus mutation of policies, "
        "bundles, baselines, AAP launches, and the remediation workflow.",
        capabilities=[
            "Upload policies and run IR extract / Rego generate",
            "Edit, approve, reject, and publish policy targets",
            "Fork from the standard library and republish from parents",
            "Build tenant bundles",
            "Manually import baseline snapshots",
            "Launch AAP job templates",
            "Open, assign, submit, approve, reject, and reopen remediation items",
        ],
    ),
    RoleCapability(
        name="account_owner",
        description="Tenant admin. Everything an editor can do, plus "
        "management of host mappings (which hostnames are in scope for "
        "this tenant's AAP launches).",
        capabilities=[
            "Manage tenant_host_mapping rows (create / delete)",
        ],
    ),
]


# ── Endpoint ─────────────────────────────────────────────────────────


@router.get(
    "",
    response_model=PermissionsResponse,
    # `by_alias=True` so the `self_` field serializes as `self` on the
    # wire (matching what frontend/src/types reads).
    response_model_by_alias=True,
)
async def get_permissions(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> PermissionsResponse:
    """Return the tenant's roster + the static role-capability matrix.

    Strictly tenant-scoped — the query filters by the session's
    `tenant_id` and the response never mentions any other tenant's
    rows, even if the schema would allow it.
    """
    rows = await pool.fetch(
        """
        SELECT id, email::text AS email, display_name, role
          FROM tenant_users
         WHERE tenant_id = $1
           AND disabled_at IS NULL
         ORDER BY role DESC, email ASC
        """,
        tenant_user["tenant_id"],
    )

    caller_id = tenant_user["tenant_user_id"]
    users = [
        PermissionUser(
            tenant_user_id=row["id"],
            email=row["email"],
            display_name=row["display_name"],
            role=row["role"],
            self_=(row["id"] == caller_id),
        )
        for row in rows
    ]

    return PermissionsResponse(users=users, roles=_ROLE_CATALOG)
