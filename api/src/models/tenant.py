"""Pydantic models for tenant + token admin endpoints."""
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, HttpUrl

Tier = Literal["free", "standard", "premium", "airgapped"]
Status = Literal["pending", "active", "suspended", "deleted"]


class TenantCreate(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    contact_email: EmailStr | None = None
    tier: Tier = "standard"
    aac_bridge_url: HttpUrl | None = None
    aac_bridge_verify_ssl: bool = True
    notes: str | None = None


class TenantUpdate(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    contact_email: EmailStr | None = None
    tier: Tier | None = None
    aac_bridge_url: HttpUrl | None = None
    aac_bridge_verify_ssl: bool | None = None
    status: Status | None = None
    notes: str | None = None


class Tenant(BaseModel):
    id: UUID
    display_name: str
    contact_email: str | None = None
    tier: Tier
    aac_bridge_url: str | None = None
    aac_bridge_verify_ssl: bool
    status: Status
    notes: str | None = None
    created_at: datetime
    updated_at: datetime


class TokenCreate(BaseModel):
    description: str | None = Field(default=None, max_length=255)
    scopes: list[str] = Field(default_factory=lambda: ["inventory_pull", "cve_feed"])


class TokenInfo(BaseModel):
    """Token metadata only — never includes the plaintext secret."""
    id: UUID
    tenant_id: UUID
    token_id: str
    description: str | None = None
    scopes: list[str]
    created_at: datetime
    created_by: str | None = None
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


class TokenCreated(TokenInfo):
    """Returned exactly once at creation — contains the plaintext secret."""
    token_secret: str = Field(
        ...,
        description="Plaintext token_secret. Shown once at creation; cannot be retrieved later.",
    )


class TokenRevoke(BaseModel):
    reason: str | None = Field(default=None, max_length=500)
