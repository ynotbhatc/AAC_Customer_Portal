"""BundleStore abstraction for raw policy uploads.

Per design §2 (MVP must not foreclose final product), every storage
decision goes through this interface. The MVP uses `PgBundleStore`
which stores bytes in the portal database. Later tiers can swap to
S3 / Minio / customer-hosted git / air-gap bundle pipeline without
touching the routers — they only see opaque `storage_key` strings.

Key format is implementation-defined. PgBundleStore returns
`pgupload:<uuid>`. Future stores would use different prefixes:
`s3://bucket/path`, `git+https://...#sha`, etc. The dispatch in
`get_bundle_store()` picks the right backend by prefix.

The router stores the returned key in `customer_policies.source_file_storage_key`.
"""
from __future__ import annotations

import hashlib
from typing import Protocol
from uuid import UUID

import asyncpg


class BundleStore(Protocol):
    """Minimal interface every concrete store must satisfy."""

    async def put(
        self,
        *,
        tenant_id: UUID,
        uploaded_by_user_id: UUID | None,
        filename: str,
        sniffed_mime: str,
        raw: bytes,
        extracted_text: str,
        conn: asyncpg.Connection,
    ) -> tuple[str, UUID]:
        """Persist raw + extracted bytes (source-document path).

        Returns `(storage_key, upload_id)`. The router stores
        `storage_key` on customer_policies; `upload_id` is what the
        upload-listing UI references.

        Runs inside the caller's transaction (`conn`) so the upload
        row and the customer_policies row commit atomically.
        """
        ...

    async def put_rego(
        self,
        *,
        tenant_id: UUID,
        uploaded_by_user_id: UUID | None,
        filename: str,
        rego_text: str,
        conn: asyncpg.Connection,
    ) -> tuple[str, UUID]:
        """Persist a generated Rego artifact.

        Returns `(storage_key, artifact_id)`. The router stores
        `storage_key` on customer_policy_targets.rego_storage_key.

        Per PR 7 advisor brief: reuses the policy_uploads table rather
        than introducing a parallel artifact table; the only thing that
        differs is the key prefix (`pgrego:` vs `pgupload:`) and the
        sniffed_mime label.
        """
        ...


class PgBundleStore:
    """MVP store: raw bytes live in `policy_uploads.raw_bytes` (bytea).

    Atomic with the customer_policies row because both inserts use
    the same connection / transaction. SHA-256 of the bytes lets the
    router cheaply detect duplicate uploads if desired (no automatic
    dedup at this layer — that's a router-level decision).
    """

    async def put(
        self,
        *,
        tenant_id: UUID,
        uploaded_by_user_id: UUID | None,
        filename: str,
        sniffed_mime: str,
        raw: bytes,
        extracted_text: str,
        conn: asyncpg.Connection,
    ) -> tuple[str, UUID]:
        sha = hashlib.sha256(raw).hexdigest()
        row = await conn.fetchrow(
            """
            INSERT INTO policy_uploads
                (tenant_id, uploaded_by_user_id, original_filename,
                 sniffed_mime, byte_size, byte_sha256, raw_bytes,
                 extracted_text, extracted_text_chars)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            """,
            tenant_id,
            uploaded_by_user_id,
            filename,
            sniffed_mime,
            len(raw),
            sha,
            raw,
            extracted_text,
            len(extracted_text),
        )
        upload_id: UUID = row["id"]
        return f"pgupload:{upload_id}", upload_id

    async def put_rego(
        self,
        *,
        tenant_id: UUID,
        uploaded_by_user_id: UUID | None,
        filename: str,
        rego_text: str,
        conn: asyncpg.Connection,
    ) -> tuple[str, UUID]:
        raw = rego_text.encode("utf-8")
        sha = hashlib.sha256(raw).hexdigest()
        row = await conn.fetchrow(
            """
            INSERT INTO policy_uploads
                (tenant_id, uploaded_by_user_id, original_filename,
                 sniffed_mime, byte_size, byte_sha256, raw_bytes,
                 extracted_text, extracted_text_chars)
            VALUES ($1, $2, $3, 'application/rego', $4, $5, $6, $7, $8)
            RETURNING id
            """,
            tenant_id,
            uploaded_by_user_id,
            filename,
            len(raw),
            sha,
            raw,
            rego_text,
            len(rego_text),
        )
        artifact_id: UUID = row["id"]
        return f"pgrego:{artifact_id}", artifact_id


_default = PgBundleStore()


def get_bundle_store() -> BundleStore:
    """Return the active BundleStore implementation. Future versions
    will pick by tenant tier (e.g. air-gapped customers get an S3 or
    customer-git impl); MVP returns the Postgres impl for everyone."""
    return _default
