"""TOTP MFA enrollment endpoints.

Two-step enrollment so users prove the secret made it into their
authenticator app before we flip mfa_enrolled on:

    POST /portal/v1/me/mfa/totp/setup
        Generates a pending factor row, returns the otpauth URI +
        raw secret. The row is "draft" — secret_hash holds the
        plaintext base32 secret (the only place we ever store it
        unhashed, because we need to verify codes against it later).
        It is NOT enrolled until /confirm flips the row.

        # NOTE: secret_hash stores the TOTP secret in PLAINTEXT
        #       (base32). RFC 6238 doesn't admit a one-way hash —
        #       the server must recompute HOTP(secret, counter)
        #       on every login. Threat model: anyone with read
        #       access to tenant_user_mfa_factors can forge codes,
        #       same as the existing tenant_tokens.token_secret_plaintext
        #       trade-off. Encrypt at rest is the production gap;
        #       Fernet/KMS is its own PR.

    POST /portal/v1/me/mfa/totp/confirm
        User submits the 6-digit code their app shows. Server verifies
        against the pending row. On success: flips mfa_enrolled on
        the user, inserts 10 backup-code rows (each one-time), and
        returns them ONCE.
"""
from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

import asyncpg
import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Response

from ..core.portal_db import get_portal_pool
from ..core.sessions import require_tenant_user
from ..core.totp import (
    new_backup_codes,
    new_totp_secret,
    otpauth_uri,
    verify_totp,
)
from ..models.tenant_mfa import (
    BackupCodesResponse,
    MfaFactorSummary,
    TotpConfirmRequest,
    TotpSetupResponse,
)


router = APIRouter(prefix="/portal/v1/me/mfa", tags=["portal:mfa"])


@router.get("/factors", response_model=list[MfaFactorSummary])
async def list_factors(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> list[dict]:
    rows = await pool.fetch(
        """
        SELECT id, factor_type, factor_label, enrolled_at, last_used_at, revoked_at
          FROM tenant_user_mfa_factors
         WHERE tenant_user_id = $1
         ORDER BY enrolled_at DESC
        """,
        tenant_user["tenant_user_id"],
    )
    return [dict(r) for r in rows]


@router.post("/totp/setup", response_model=TotpSetupResponse, status_code=201)
async def totp_setup(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> TotpSetupResponse:
    # If an active TOTP factor already exists, refuse — the user must
    # revoke it (PR 5 / future endpoint) before enrolling another.
    existing = await pool.fetchrow(
        """
        SELECT id FROM tenant_user_mfa_factors
         WHERE tenant_user_id = $1
           AND factor_type = 'totp'
           AND revoked_at IS NULL
        """,
        tenant_user["tenant_user_id"],
    )
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail="totp already enrolled; revoke the existing factor first",
        )

    secret = new_totp_secret()
    # Insert as a "draft" factor (enrolled_at = now() because the
    # column is NOT NULL, but factor_label='pending_setup' signals
    # the confirm step hasn't run yet). The confirm endpoint updates
    # factor_label to a friendly name once verified.
    row = await pool.fetchrow(
        """
        INSERT INTO tenant_user_mfa_factors
            (tenant_user_id, factor_type, factor_label, secret_hash)
        VALUES ($1, 'totp', 'pending_setup', $2)
        RETURNING id
        """,
        tenant_user["tenant_user_id"],
        secret,
    )

    return TotpSetupResponse(
        factor_id=row["id"],
        otpauth_uri=otpauth_uri(secret=secret, account_label=tenant_user["email"]),
        secret=secret,
    )


@router.post("/totp/confirm", response_model=BackupCodesResponse)
async def totp_confirm(
    body: TotpConfirmRequest,
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
) -> BackupCodesResponse:
    row = await pool.fetchrow(
        """
        SELECT id, secret_hash, factor_label
          FROM tenant_user_mfa_factors
         WHERE id = $1
           AND tenant_user_id = $2
           AND factor_type = 'totp'
           AND revoked_at IS NULL
        """,
        body.factor_id,
        tenant_user["tenant_user_id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="factor not found")
    if row["factor_label"] != "pending_setup":
        raise HTTPException(status_code=409, detail="factor already confirmed")

    if not verify_totp(secret=row["secret_hash"], code=body.code):
        raise HTTPException(status_code=400, detail="incorrect code")

    backup_codes = new_backup_codes()

    # Single transaction: promote the draft TOTP to confirmed, set the
    # user's mfa_enrolled flag, insert the backup-code rows. If any
    # step fails, the user can retry without dangling state.
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE tenant_user_mfa_factors
                   SET factor_label = 'authenticator',
                       enrolled_at = now()
                 WHERE id = $1
                """,
                body.factor_id,
            )
            await conn.execute(
                "UPDATE tenant_users SET mfa_enrolled = true WHERE id = $1",
                tenant_user["tenant_user_id"],
            )
            # Each backup code is its own row so consumption is one
            # UPDATE (set revoked_at). Hashes use bcrypt cost 10 —
            # codes are 8 chars (~48 bits), cost 12 would burn ~50ms
            # per backup attempt with no security benefit since the
            # codes are random.
            for code in backup_codes:
                hashed = bcrypt.hashpw(code.encode("utf-8"), bcrypt.gensalt(rounds=10)).decode("utf-8")
                await conn.execute(
                    """
                    INSERT INTO tenant_user_mfa_factors
                        (tenant_user_id, factor_type, factor_label, secret_hash)
                    VALUES ($1, 'backup_codes', 'recovery', $2)
                    """,
                    tenant_user["tenant_user_id"],
                    hashed,
                )

    return BackupCodesResponse(backup_codes=backup_codes)


@router.post("/factors/{factor_id}/revoke", status_code=204, response_class=Response, response_model=None)
async def revoke_factor(
    tenant_user: Annotated[dict[str, Any], Depends(require_tenant_user)],
    pool: Annotated[asyncpg.Pool, Depends(get_portal_pool)],
    factor_id: UUID,
) -> None:
    # Revoke is allowed even mid-setup (cancels the pending enrollment).
    row = await pool.fetchrow(
        """
        UPDATE tenant_user_mfa_factors
           SET revoked_at = now()
         WHERE id = $1
           AND tenant_user_id = $2
           AND revoked_at IS NULL
        RETURNING factor_type
        """,
        factor_id,
        tenant_user["tenant_user_id"],
    )
    if row is None:
        raise HTTPException(status_code=404, detail="factor not found or already revoked")

    # If the user just revoked their TOTP, drop mfa_enrolled. Backup
    # codes alone don't satisfy enrollment.
    still_enrolled = await pool.fetchval(
        """
        SELECT EXISTS (
            SELECT 1 FROM tenant_user_mfa_factors
             WHERE tenant_user_id = $1
               AND factor_type = 'totp'
               AND revoked_at IS NULL
               AND factor_label != 'pending_setup'
        )
        """,
        tenant_user["tenant_user_id"],
    )
    if not still_enrolled:
        await pool.execute(
            "UPDATE tenant_users SET mfa_enrolled = false WHERE id = $1",
            tenant_user["tenant_user_id"],
        )
