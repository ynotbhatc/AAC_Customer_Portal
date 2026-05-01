"""
OIDC authentication middleware for FastAPI.

Validates bearer tokens issued by Keycloak / Red Hat SSO.
Token validation uses the Keycloak JWKS endpoint (public keys only —
no client secret needed for RS256 JWT verification).

Configuration (via .env):
  OIDC_ISSUER   — e.g. https://sso.example.com/realms/aac
  OIDC_CLIENT_ID — e.g. aac-portal
  OIDC_ENABLED  — set false to skip auth (dev mode)
"""

from __future__ import annotations

import httpx
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from .config import get_settings

_bearer = HTTPBearer(auto_error=False)


class TokenClaims(BaseModel):
    sub: str
    preferred_username: str = ""
    email: str = ""
    name: str = ""
    realm_access: dict = {}

    @property
    def roles(self) -> list[str]:
        return self.realm_access.get("roles", [])

    def require_role(self, role: str) -> None:
        if role not in self.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' required",
            )


@lru_cache(maxsize=1)
def _get_jwks() -> dict:
    """Fetch and cache JWKS from Keycloak. Cache busts on process restart."""
    s = get_settings()
    url = f"{s.oidc_issuer}/protocol/openid-connect/certs"
    resp = httpx.get(url, timeout=10, verify=s.oidc_verify_ssl)
    resp.raise_for_status()
    return resp.json()


def _decode_token(token: str) -> TokenClaims:
    s = get_settings()
    jwks = _get_jwks()
    try:
        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=s.oidc_client_id,
            options={"verify_exp": True},
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return TokenClaims(**payload)


async def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Security(_bearer)
    ] = None,
) -> TokenClaims:
    s = get_settings()

    if not s.oidc_enabled:
        # Dev mode — return a synthetic admin user
        return TokenClaims(
            sub="dev-user",
            preferred_username="dev",
            email="dev@localhost",
            name="Dev User",
            realm_access={"roles": ["admin", "viewer"]},
        )

    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _decode_token(credentials.credentials)


# Convenience dependency aliases
CurrentUser = Annotated[TokenClaims, Depends(get_current_user)]
