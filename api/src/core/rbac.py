"""Role-based access control for tenant users.

Two-part design:

1. `Role` — string-enum of the three roles in the schema (matches the
   CHECK constraint on tenant_users.role).

2. `require_role(min_role)` — a FastAPI dependency factory consumed
   by downstream PRs (PR 4+ when policy endpoints land). It checks that
   the authenticated tenant_user's role is at or above `min_role` in
   the ordered hierarchy.

This module is intentionally narrow. Session/login (the thing that
produces the tenant_user dict the dependency reads) is added in PR 3
alongside TOTP MFA. PR 2 only ships the role helper so PR 4's policy
endpoints can be authored against a stable interface.

Role hierarchy (least → most privileged):
    viewer < editor < account_owner

The Owner role inherits everything below it. Editor inherits viewer.
"""
from __future__ import annotations

from enum import IntEnum
from typing import Any, Callable, Coroutine

from fastapi import Depends, HTTPException


class Role(IntEnum):
    """Ordered tenant_user role hierarchy.

    The integer value encodes the privilege level — higher means more.
    Use `Role.from_str` to convert the DB-stored string. Endpoint
    checks should always pass the symbolic name, not the int.
    """
    VIEWER = 1
    EDITOR = 2
    ACCOUNT_OWNER = 3

    @classmethod
    def from_str(cls, value: str) -> "Role":
        mapping = {
            "viewer": cls.VIEWER,
            "editor": cls.EDITOR,
            "account_owner": cls.ACCOUNT_OWNER,
        }
        try:
            return mapping[value]
        except KeyError as exc:
            raise ValueError(f"unknown role: {value!r}") from exc

    def to_str(self) -> str:
        return {
            Role.VIEWER: "viewer",
            Role.EDITOR: "editor",
            Role.ACCOUNT_OWNER: "account_owner",
        }[self]


def has_role(actor_role: str, min_role: str) -> bool:
    """Pure-function check, no FastAPI plumbing — useful for tests and
    direct calls from background jobs that don't go through a request."""
    return Role.from_str(actor_role) >= Role.from_str(min_role)


def require_role(min_role: str) -> Callable[..., Coroutine[Any, Any, dict[str, Any]]]:
    """FastAPI dependency factory.

    Returns a dependency that pulls the current `tenant_user` from
    the request context (populated by the session/MFA middleware
    landing in PR 3) and rejects with 403 if their role is below
    `min_role`.

    Usage (PR 4+):
        @router.post("/policies", dependencies=[Depends(require_role("editor"))])
        async def create_policy(...):
            ...

    Until PR 3 wires the session dependency, calling this from a
    router would 503 — that's fine, no router uses it yet.
    """
    # Validate at import time so a typo surfaces immediately, not at
    # first request.
    _ = Role.from_str(min_role)

    async def _checker(
        tenant_user: dict[str, Any] = Depends(_current_tenant_user_placeholder),
    ) -> dict[str, Any]:
        actor_role = tenant_user.get("role")
        if not actor_role or not has_role(actor_role, min_role):
            raise HTTPException(
                status_code=403,
                detail=f"requires role >= {min_role}",
            )
        return tenant_user

    return _checker


async def _current_tenant_user_placeholder() -> dict[str, Any]:
    """Placeholder until PR 3 provides the real session dependency.

    Any router that depends on require_role() before PR 3 lands will
    surface a clear 503 instead of silently returning anonymous-shaped
    dicts. PR 3 will replace this import path with the real session
    resolver.
    """
    raise HTTPException(
        status_code=503,
        detail="tenant_user session not configured — PR 3 (session + MFA) not yet landed",
    )
