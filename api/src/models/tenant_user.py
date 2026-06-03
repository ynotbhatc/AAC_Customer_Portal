"""Pydantic models for tenant_user admin endpoints.

Tenant users are human end-users scoped to a single tenant — distinct
from the M2M `tenant_tokens` (which authenticate the customer's AAC
bridge polling the portal). Schema lives in migration 006.
"""
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

Role = Literal["account_owner", "editor", "viewer"]


class TenantUserCreate(BaseModel):
    email: EmailStr
    display_name: str | None = Field(default=None, max_length=255)
    role: Role = "viewer"
    oidc_subject: str | None = Field(
        default=None,
        max_length=255,
        description="Subject claim from the tenant's IdP if SSO is configured. "
        "NULL for username/password users — password is set via a separate "
        "set-password endpoint (PR 3, alongside MFA enrollment).",
    )


class TenantUserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    role: Role | None = None
    oidc_subject: str | None = Field(default=None, max_length=255)


class TenantUser(BaseModel):
    """Public-safe view — never includes password_hash or MFA secrets."""
    id: UUID
    tenant_id: UUID
    email: str
    display_name: str | None = None
    role: Role
    oidc_subject: str | None = None
    mfa_enrolled: bool
    mfa_required: bool
    last_login_at: datetime | None = None
    disabled_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
