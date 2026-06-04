"""Customer-bundle assembler.

Pulls every `review_status='approved'` Rego artifact for a tenant,
hands them to `opa build` over the per-tenant package mount
(customer/<tenant_slug>/...), and returns the resulting tar.gz
bytes ready for signing + persisting.

Match advisor's "don't invent a parallel format" guidance: the output
is a standard OPA bundle. The AAC bridge runs `opa run --bundle` over
it directly — no portal-specific format translation in the loader.

Subprocess invocation note: asyncio.create_subprocess_exec takes argv
as a list, never spawns a shell — safe even if rego_text contains
shell metacharacters.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from typing import Any

import asyncpg

from .config import get_settings
from .rego_validator import OpaBinaryMissing, OpaVersionTooOld, assert_opa_available


_TENANT_SLUG_RE = re.compile(r"[^a-z0-9]")


def _tenant_slug(tenant_id: str) -> str:
    """Same convention as rego_generator._tenant_slug."""
    return "t_" + _TENANT_SLUG_RE.sub("_", tenant_id.lower())


@dataclass
class BundleBuildResult:
    bundle_bytes: bytes
    bundle_sha256: str
    target_count: int
    customer_policy_ids: list[str]
    excluded_targets: list[dict[str, Any]]
    manifest: dict[str, Any]


async def build_tenant_bundle(
    *,
    pool: asyncpg.Pool,
    tenant_id: str,
) -> BundleBuildResult:
    """Build a fresh OPA bundle from this tenant's approved targets.

    Walks customer_policies in 'published' status, pulls each approved
    customer_policy_targets row's Rego from policy_uploads (storage_key
    has 'pgrego:<uuid>' format from PR 7's PgBundleStore.put_rego),
    arranges them under customer/<tenant_slug>/<policy_id>/<target>.rego
    inside a temp dir, then shells out to `opa build`.
    """
    await assert_opa_available()
    s = get_settings()

    rows = await pool.fetch(
        """
        SELECT cp.id          AS policy_id,
               cp.version_semver,
               cp.name        AS policy_name,
               cpt.id         AS target_id,
               cpt.target_system,
               cpt.target_subtype,
               cpt.rego_storage_key,
               cpt.review_status,
               cpt.generation_method,
               cpt.confidence_score
          FROM customer_policies cp
          JOIN customer_policy_targets cpt ON cpt.customer_policy_id = cp.id
         WHERE cp.tenant_id = $1
           AND cp.status = 'published'
         ORDER BY cp.id, cpt.target_system, cpt.target_subtype NULLS FIRST
        """,
        tenant_id,
    )

    included: list[asyncpg.Record] = []
    excluded: list[dict[str, Any]] = []
    for r in rows:
        if r["review_status"] == "approved":
            included.append(r)
        else:
            excluded.append(
                {
                    "customer_policy_id": str(r["policy_id"]),
                    "target_id": str(r["target_id"]),
                    "target_system": r["target_system"],
                    "review_status": r["review_status"],
                    "reason": "not approved",
                }
            )

    slug = _tenant_slug(tenant_id)
    policy_ids: list[str] = []

    with tempfile.TemporaryDirectory(prefix="bundle_build_") as td:
        root = os.path.join(td, "src")
        os.makedirs(root, exist_ok=True)

        for r in included:
            key = r["rego_storage_key"]
            if not key or not key.startswith("pgrego:"):
                excluded.append(
                    {
                        "customer_policy_id": str(r["policy_id"]),
                        "target_id": str(r["target_id"]),
                        "target_system": r["target_system"],
                        "review_status": r["review_status"],
                        "reason": "rego artifact not in pg store",
                    }
                )
                continue

            artifact_id = key.split(":", 1)[1]
            rego_row = await pool.fetchrow(
                "SELECT extracted_text FROM policy_uploads WHERE id = $1::uuid",
                artifact_id,
            )
            if rego_row is None:
                excluded.append(
                    {
                        "customer_policy_id": str(r["policy_id"]),
                        "target_id": str(r["target_id"]),
                        "target_system": r["target_system"],
                        "review_status": r["review_status"],
                        "reason": "rego artifact row missing",
                    }
                )
                continue

            policy_dir = os.path.join(
                root, "customer", slug, str(r["policy_id"])
            )
            os.makedirs(policy_dir, exist_ok=True)
            target_label = r["target_system"]
            if r["target_subtype"]:
                target_label = f"{target_label}_{r['target_subtype']}"
            rego_path = os.path.join(policy_dir, f"{target_label}.rego")
            with open(rego_path, "w", encoding="utf-8") as fh:
                fh.write(rego_row["extracted_text"])

            sid = str(r["policy_id"])
            if sid not in policy_ids:
                policy_ids.append(sid)

        bundle_path = os.path.join(td, "bundle.tar.gz")
        try:
            proc = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    s.opa_binary_path,
                    "build",
                    "--bundle",
                    "--v1-compatible",
                    "--output",
                    bundle_path,
                    root,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                ),
                timeout=s.opa_build_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            raise RuntimeError(
                f"opa build timed out after {s.opa_build_timeout_seconds}s"
            ) from exc
        stdout_b, stderr_b = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(
                "opa build failed: "
                + stderr_b.decode("utf-8", errors="replace")[:1000]
            )

        with open(bundle_path, "rb") as fh:
            bundle_bytes = fh.read()

    bundle_sha = hashlib.sha256(bundle_bytes).hexdigest()
    manifest = {
        "tenant_id": tenant_id,
        "tenant_slug": slug,
        "bundle_sha256": bundle_sha,
        "bundle_byte_size": len(bundle_bytes),
        "target_count": len(included) - sum(
            1 for e in excluded if e["reason"] != "not approved"
        ),
        "customer_policy_ids": policy_ids,
        "targets": [
            {
                "target_id": str(r["target_id"]),
                "policy_id": str(r["policy_id"]),
                "target_system": r["target_system"],
                "target_subtype": r["target_subtype"],
                "generation_method": r["generation_method"],
                "confidence_score": r["confidence_score"],
            }
            for r in included
        ],
        "excluded": excluded,
    }

    return BundleBuildResult(
        bundle_bytes=bundle_bytes,
        bundle_sha256=bundle_sha,
        target_count=manifest["target_count"],
        customer_policy_ids=policy_ids,
        excluded_targets=excluded,
        manifest=manifest,
    )
