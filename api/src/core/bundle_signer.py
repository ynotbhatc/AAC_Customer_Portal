"""ed25519 + JWS-style signing for policy bundles.

The signed envelope is a compact JSON document binding the bundle's
sha256 + tenant + bundle metadata to the portal's ed25519 key. The
AAC bridge embeds the portal's public key (delivered out-of-band at
tenant onboarding) and verifies the envelope before loading the
bundle into OPA.

Why ed25519 + JWS, not cosign / OCI signatures:
  - bridge runs in customer env, often air-gapped — can't reach the
    portal at verify time, so no online lookup
  - ed25519 verification is a one-call libsodium op; cosign would
    pull a verification toolchain we don't need
  - JWS envelope is a single JSON file the bridge can parse without
    a custom format library

Key management:
  - Private key file is read once at module import (cheap) — never
    held in memory longer than needed for sign()
  - Public key is exposed via GET /portal/v1/bundles/signing-key
    (unauthenticated) so the bridge can fetch + pin at onboarding
  - Rotation is a separate concern (operator script swaps the file
    and bumps signing_key_id); bridge embedding remains stable until
    the operator distributes the new public key
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone

from nacl.signing import SigningKey, VerifyKey

from .config import get_settings


class SigningKeyMissing(RuntimeError):
    """Raised when bundle_signing_key_path is empty or unreadable.
    Routers translate to 503 — operator hasn't completed setup."""


_signer_cache: SigningKey | None = None


def _load_signing_key() -> SigningKey:
    """Read the ed25519 private key from disk.

    Format: raw 32-byte seed, base64 or hex-encoded in a single-line
    text file. Operator's generation script writes one of these formats.
    """
    global _signer_cache
    if _signer_cache is not None:
        return _signer_cache

    s = get_settings()
    if not s.bundle_signing_key_path:
        raise SigningKeyMissing(
            "bundle_signing_key_path not configured; "
            "run scripts/generate_bundle_key.py to bootstrap"
        )
    if not os.path.isfile(s.bundle_signing_key_path):
        raise SigningKeyMissing(
            f"bundle_signing_key_path={s.bundle_signing_key_path!r} not found"
        )

    with open(s.bundle_signing_key_path, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()

    # Accept base64 (44 chars w/ padding) or hex (64 chars).
    seed: bytes
    if len(raw) == 64 and all(c in "0123456789abcdefABCDEF" for c in raw):
        seed = bytes.fromhex(raw)
    else:
        try:
            seed = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise SigningKeyMissing(f"signing key not valid base64 or hex: {exc!s}") from exc
        if len(seed) != 32:
            raise SigningKeyMissing(
                f"signing key seed must be 32 bytes; got {len(seed)}"
            )

    _signer_cache = SigningKey(seed)
    return _signer_cache


def public_key_b64() -> str:
    """Return the operator's ed25519 public key as base64.

    Served by the unauthenticated `/portal/v1/bundles/signing-key`
    endpoint for bridge embedding.
    """
    return base64.b64encode(_load_signing_key().verify_key.encode()).decode("ascii")


def sign_bundle(
    *,
    tenant_id: str,
    bundle_sha256: str,
    bundle_byte_size: int,
    target_count: int,
    customer_policy_ids: list[str],
) -> bytes:
    """Produce the signed envelope for a bundle build.

    Envelope shape (JSON, one line):

        {
          "v": 1,
          "alg": "ed25519",
          "key_id": "<operator-rotation-key-id>",
          "payload": {
              "tenant_id":           "<uuid>",
              "bundle_sha256":       "<hex>",
              "bundle_byte_size":    <int>,
              "target_count":        <int>,
              "customer_policy_ids": [...],
              "signed_at":           "<RFC3339>"
          },
          "signature": "<base64(ed25519(canonical_payload_json))>"
        }

    The bridge re-canonicalises the payload (sorted keys, compact
    separators) before verifying, so any in-flight reformatting
    invalidates the signature without breaking equality.
    """
    s = get_settings()
    signer = _load_signing_key()

    payload = {
        "tenant_id": tenant_id,
        "bundle_sha256": bundle_sha256,
        "bundle_byte_size": bundle_byte_size,
        "target_count": target_count,
        "customer_policy_ids": customer_policy_ids,
        "signed_at": datetime.now(tz=timezone.utc).isoformat(),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signed = signer.sign(canonical)
    envelope = {
        "v": 1,
        "alg": "ed25519",
        "key_id": s.bundle_signing_key_id,
        "payload": payload,
        "signature": base64.b64encode(signed.signature).decode("ascii"),
    }
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")
