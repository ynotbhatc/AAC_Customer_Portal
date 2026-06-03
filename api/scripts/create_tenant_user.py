#!/usr/bin/env python3
"""
Bootstrap CLI for creating a tenant_user before the admin UI is wired
up — typically used during onboarding to seed the first account_owner
for a freshly-created tenant.

Reads portal DB connection from env vars matching the running API:
    PORTAL_PG_HOST, PORTAL_PG_PORT, PORTAL_PG_DATABASE,
    PORTAL_PG_USER, PORTAL_PG_PASSWORD

Usage:
    python scripts/create_tenant_user.py \\
        --tenant-id <uuid> \\
        --email security-lead@acme.com \\
        --display-name "Acme Security Lead" \\
        --role account_owner

The user is created without a password and without MFA enrolled —
they finish setup via the self-service set-password flow (PR 3).
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from uuid import UUID

import asyncpg


VALID_ROLES = ("account_owner", "editor", "viewer")


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", required=True, help="Tenant UUID")
    parser.add_argument("--email", required=True, help="User email (unique within tenant)")
    parser.add_argument("--display-name", default=None, help="Optional display name")
    parser.add_argument(
        "--role",
        choices=VALID_ROLES,
        default="viewer",
        help="Role assignment (default: viewer)",
    )
    parser.add_argument(
        "--oidc-subject",
        default=None,
        help="If the tenant uses SSO, the user's subject claim from their IdP",
    )
    args = parser.parse_args()

    try:
        tenant_uuid = UUID(args.tenant_id)
    except ValueError:
        print(f"ERROR: invalid tenant UUID: {args.tenant_id}", file=sys.stderr)
        return 2

    pool = await asyncpg.create_pool(
        host=os.environ.get("PORTAL_PG_HOST", "localhost"),
        port=int(os.environ.get("PORTAL_PG_PORT", "5432")),
        database=os.environ.get("PORTAL_PG_DATABASE", "aac_portal"),
        user=os.environ.get("PORTAL_PG_USER", "aac_portal_app"),
        password=os.environ.get("PORTAL_PG_PASSWORD", ""),
        min_size=1,
        max_size=2,
    )
    try:
        tenant = await pool.fetchrow(
            "SELECT id, display_name, status FROM tenants WHERE id = $1",
            tenant_uuid,
        )
        if tenant is None:
            print(f"ERROR: tenant {tenant_uuid} not found", file=sys.stderr)
            return 1
        if tenant["status"] == "deleted":
            print(f"ERROR: tenant {tenant_uuid} is deleted", file=sys.stderr)
            return 1

        try:
            row = await pool.fetchrow(
                """
                INSERT INTO tenant_users
                    (tenant_id, email, display_name, role,
                     oidc_subject, mfa_required)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id, email::text, role, mfa_required, created_at
                """,
                tenant_uuid,
                args.email,
                args.display_name,
                args.role,
                args.oidc_subject,
                args.role in ("account_owner", "editor"),
            )
        except asyncpg.UniqueViolationError:
            print(
                f"ERROR: email {args.email!r} already exists for tenant {tenant_uuid}",
                file=sys.stderr,
            )
            return 1

        print("User created.")
        print(f"  user_id:       {row['id']}")
        print(f"  tenant:        {tenant['display_name']} ({tenant_uuid})")
        print(f"  email:         {row['email']}")
        print(f"  role:          {row['role']}")
        print(f"  mfa_required:  {row['mfa_required']}")
        print(f"  created_at:    {row['created_at']}")
        print("")
        print("Next steps:")
        print(f"  - Send {row['email']} a set-password link (PR 3 endpoint).")
        if row["mfa_required"]:
            print("  - MFA enrollment is mandatory before this user can perform writes.")
        return 0
    finally:
        await pool.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
