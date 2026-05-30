"""
Operator-admin auth dependency for portal-management endpoints
(create tenant, regenerate token, etc.).

Reads PORTAL_ADMIN_TOKEN from the environment (via Settings). Returns
the matching bearer or raises 401/403.

This is a deliberately minimal scheme for the no-customer-yet phase.
Replace with SSO/OIDC + an operators table when the portal goes prod.
"""
from fastapi import Header, HTTPException
from .config import get_settings


async def require_admin(authorization: str | None = Header(default=None)) -> None:
    s = get_settings()
    if not s.portal_admin_token:
        raise HTTPException(
            status_code=503,
            detail="PORTAL_ADMIN_TOKEN not configured on the server",
        )
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if not token or token != s.portal_admin_token:
        raise HTTPException(status_code=403, detail="not authorized")
