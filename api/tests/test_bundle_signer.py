"""Tests for core/bundle_signer — ed25519 envelope signing + bridge-side
verify equivalence.

The signing path is security-critical: any reformatting of the canonical
payload between sign and verify silently invalidates customer bundles.
These tests pin the canonical form so a future refactor of the JSON
serialization can't introduce a verify mismatch.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from nacl.signing import SigningKey, VerifyKey


@pytest.fixture(autouse=True)
def reset_settings_cache():
    """Settings are wrapped in `@lru_cache`; tests that monkeypatch env
    vars need a fresh Settings each time. Cleared before AND after so
    test order doesn't leak state."""
    from src.core.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def signing_key_file(tmp_path: Path) -> Path:
    """Generate a fresh ed25519 keypair for the test and write the
    seed in base64. Returns the private key path; the public key is
    derivable via VerifyKey(SigningKey(seed).verify_key.encode())."""
    key = SigningKey.generate()
    path = tmp_path / "portal_bundle_signing.key"
    path.write_text(base64.b64encode(bytes(key)).decode("ascii"))
    return path


def test_sign_and_verify_round_trip(signing_key_file: Path, monkeypatch) -> None:
    """Sign a payload, re-canonicalize on the bridge side, verify with
    the public key. Happy-path proof that the bridge's verifier
    sees the same bytes the signer signed."""
    monkeypatch.setenv("BUNDLE_SIGNING_KEY_PATH", str(signing_key_file))
    monkeypatch.setenv("BUNDLE_SIGNING_KEY_ID", "test-key-2026")

    # Import only after env is set so settings pick up the path.
    from src.core.bundle_signer import public_key_b64, sign_bundle
    # Reset module cache so the test owns the SigningKey load.
    import src.core.bundle_signer as bs
    bs._signer_cache = None

    envelope = sign_bundle(
        tenant_id="33333333-3333-3333-3333-333333333333",
        bundle_sha256="a" * 64,
        bundle_byte_size=1234,
        target_count=5,
        customer_policy_ids=["11111111-1111-1111-1111-111111111111"],
    )

    env = json.loads(envelope)
    assert env["v"] == 1
    assert env["alg"] == "ed25519"
    assert env["key_id"] == "test-key-2026"

    pub_b64 = public_key_b64()
    verify_key = VerifyKey(base64.b64decode(pub_b64))

    # Bridge re-canonicalizes the payload the same way the signer did.
    payload_canon = json.dumps(
        env["payload"], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    sig = base64.b64decode(env["signature"])
    verify_key.verify(payload_canon, sig)  # raises BadSignatureError on fail


def test_tamper_detected(signing_key_file: Path, monkeypatch) -> None:
    """Changing any field in the payload after signing breaks the
    signature."""
    monkeypatch.setenv("BUNDLE_SIGNING_KEY_PATH", str(signing_key_file))
    monkeypatch.setenv("BUNDLE_SIGNING_KEY_ID", "test-key-2026")
    from src.core.bundle_signer import public_key_b64, sign_bundle
    import src.core.bundle_signer as bs
    bs._signer_cache = None

    envelope = sign_bundle(
        tenant_id="t",
        bundle_sha256="a" * 64,
        bundle_byte_size=1,
        target_count=1,
        customer_policy_ids=["p"],
    )
    env = json.loads(envelope)
    verify_key = VerifyKey(base64.b64decode(public_key_b64()))

    # Tampered payload — flip bundle_sha256 to a different value.
    tampered = {**env["payload"], "bundle_sha256": "0" * 64}
    canon_t = json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = base64.b64decode(env["signature"])

    from nacl.exceptions import BadSignatureError
    with pytest.raises(BadSignatureError):
        verify_key.verify(canon_t, sig)


def test_wrong_key_rejected(signing_key_file: Path, monkeypatch) -> None:
    """A different ed25519 keypair can't validate the signature."""
    monkeypatch.setenv("BUNDLE_SIGNING_KEY_PATH", str(signing_key_file))
    monkeypatch.setenv("BUNDLE_SIGNING_KEY_ID", "test-key-2026")
    from src.core.bundle_signer import sign_bundle
    import src.core.bundle_signer as bs
    bs._signer_cache = None

    envelope = sign_bundle(
        tenant_id="t",
        bundle_sha256="a" * 64,
        bundle_byte_size=1,
        target_count=1,
        customer_policy_ids=["p"],
    )
    env = json.loads(envelope)

    # Different keypair — bridge bootstrapped against the wrong portal.
    wrong = SigningKey.generate().verify_key
    payload_canon = json.dumps(
        env["payload"], sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    sig = base64.b64decode(env["signature"])

    from nacl.exceptions import BadSignatureError
    with pytest.raises(BadSignatureError):
        wrong.verify(payload_canon, sig)


def test_signing_key_missing_raises(tmp_path: Path, monkeypatch) -> None:
    """Operator forgot to run the keygen script — signing must surface
    a clear SigningKeyMissing, not a vague IOError or NaCl exception."""
    monkeypatch.setenv("BUNDLE_SIGNING_KEY_PATH", str(tmp_path / "nonexistent.key"))
    from src.core.bundle_signer import SigningKeyMissing, sign_bundle
    import src.core.bundle_signer as bs
    bs._signer_cache = None

    with pytest.raises(SigningKeyMissing):
        sign_bundle(
            tenant_id="t",
            bundle_sha256="a" * 64,
            bundle_byte_size=1,
            target_count=1,
            customer_policy_ids=["p"],
        )


def test_canonical_form_stable(signing_key_file: Path, monkeypatch) -> None:
    """Signing the same payload twice produces a different signed_at
    timestamp (and therefore a different signature) — confirms that
    the timestamp is canonical-form-influential. Lets us know if
    someone tries to factor it out into a deterministic shape later."""
    monkeypatch.setenv("BUNDLE_SIGNING_KEY_PATH", str(signing_key_file))
    from src.core.bundle_signer import sign_bundle
    import src.core.bundle_signer as bs
    bs._signer_cache = None

    e1 = json.loads(sign_bundle(
        tenant_id="t", bundle_sha256="a" * 64, bundle_byte_size=1,
        target_count=1, customer_policy_ids=["p"]))
    e2 = json.loads(sign_bundle(
        tenant_id="t", bundle_sha256="a" * 64, bundle_byte_size=1,
        target_count=1, customer_policy_ids=["p"]))

    # signed_at differs, signature differs.
    assert e1["payload"]["signed_at"] != e2["payload"]["signed_at"]
    assert e1["signature"] != e2["signature"]
