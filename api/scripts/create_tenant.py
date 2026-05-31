#!/usr/bin/env python3
"""
Bootstrap CLI for creating a tenant + initial token before the admin UI
exists (or when the admin UI is unreachable).

Reads portal DB connection from env vars matching the running API:
    PORTAL_PG_HOST, PORTAL_PG_PORT, PORTAL_PG_DATABASE,
    PORTAL_PG_USER, PORTAL_PG_PASSWORD

Usage:
    python scripts/create_tenant.py "Acme Energy" \\
        --tier premium \\
        --email security@acme.com \\
        --aac-bridge-url https://aac.acme.com:8005

Prints the token_id + plaintext token_secret ONCE. Save them — they
cannot be retrieved later.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import string
import sys

import asyncpg
import bcrypt


TOKEN_ID_PREFIX = "aac"
TOKEN_ID_LENGTH = 16
TOKEN_SECRET_LENGTH = 48
ALPHABET = string.ascii_letters + string.digits


def _new_token_id() -> str:
    body = "".join(secrets.choice(ALPHABET) for _ in range(TOKEN_ID_LENGTH))
    return f"{TOKEN_ID_PREFIX}_{body}"


def _new_token_secret() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(TOKEN_SECRET_LENGTH))


async def main() -> int:
    parser = argparse.ArgumentParser(description="Create a tenant + initial token")
    parser.add_argument("display_name", help="Tenant display name (e.g. 'Acme Energy')")
    parser.add_argument("--tier", default="standard", choices=["free", "standard", "premium", "airgapped"])
    parser.add_argument("--email", default=None, help="Operations contact email")
    parser.add_argument("--aac-bridge-url", default=None, help="https://<host>:8005")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Skip TLS verify on bridge calls")
    parser.add_argument("--notes", default=None, help="Free-form note (compliance, sales-rep, etc.)")
    parser.add_argument("--token-desc", default="initial provisioning token")
    parser.add_argument("--created-by", default=os.environ.get("USER", "bootstrap-cli"))
    args = parser.parse_args()

    conn = await asyncpg.connect(
        host=os.environ.get("PORTAL_PG_HOST", "localhost"),
        port=int(os.environ.get("PORTAL_PG_PORT", "5432")),
        database=os.environ.get("PORTAL_PG_DATABASE", "aac_portal"),
        user=os.environ.get("PORTAL_PG_USER", "aac_portal_app"),
        password=os.environ.get("PORTAL_PG_PASSWORD", ""),
    )
    try:
        async with conn.transaction():
            tenant_row = await conn.fetchrow(
                """
                INSERT INTO tenants
                    (display_name, contact_email, tier,
                     aac_bridge_url, aac_bridge_verify_ssl, notes)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id, display_name, tier, status, created_at
                """,
                args.display_name,
                args.email,
                args.tier,
                args.aac_bridge_url,
                not args.no_verify_ssl,
                args.notes,
            )

            token_id = _new_token_id()
            token_secret = _new_token_secret()
            secret_hash = bcrypt.hashpw(
                token_secret.encode("utf-8"),
                bcrypt.gensalt(rounds=12),
            ).decode("utf-8")

            await conn.execute(
                """
                INSERT INTO tenant_tokens
                    (tenant_id, token_id, token_secret_hash,
                     token_secret_plaintext, description, created_by)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                tenant_row["id"],
                token_id,
                secret_hash,
                token_secret,   # see 004_matching.sql header re: outbound use
                args.token_desc,
                args.created_by,
            )
    finally:
        await conn.close()

    print("=" * 70)
    print("Tenant created")
    print("=" * 70)
    print(f"  tenant_id:    {tenant_row['id']}")
    print(f"  display_name: {tenant_row['display_name']}")
    print(f"  tier:         {tenant_row['tier']}")
    print(f"  status:       {tenant_row['status']}")
    print()
    print("Initial token (save these — secret is shown ONCE):")
    print(f"  token_id:     {token_id}")
    print(f"  token_secret: {token_secret}")
    print()
    print("Provide these to the customer for their 'Connect to Portal' UI:")
    print(f"  Portal URL:   <set in PORTAL_BASE_URL>")
    print(f"  Tenant ID:    {tenant_row['id']}")
    print(f"  Token ID:     {token_id}")
    print(f"  Token Secret: {token_secret}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
