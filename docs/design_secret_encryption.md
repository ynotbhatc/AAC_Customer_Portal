# Design — Secret Encryption at Rest

**Status:** draft for review — implementation deferred pending decisions
on this doc.

## Problem

Two columns currently hold sensitive material in plaintext:

| Table | Column | Why plaintext today |
|-------|--------|---------------------|
| `tenant_tokens` | `token_secret_plaintext` (migration 004:9-24) | The operator needs to display the secret once at issue time; the bridge stores it offline for M2M auth. We also store a bcrypt hash for verification, but the plaintext is referenced by `feeds/inventory_puller.py` when the portal makes outbound calls on behalf of a tenant. |
| `tenant_user_mfa_factors` | `totp_secret_plaintext` (me_mfa.py:13-20) | TOTP requires the actual seed to compute the current 6-digit code. Hashing is not an option — verification reproduces the code. |

Anyone with read access to the portal's PostgreSQL database can recover
every bridge credential and every TOTP seed. The columns are explicitly
flagged as TODO-for-encryption in the migration comment, but the work
has never landed.

## Recommendation

Adopt **envelope encryption** with a pluggable Key Encryption Key (KEK)
backend. Primary backend: **HashiCorp Vault Transit**. Secondary backends
behind the same interface for AWS/Azure/GCP customers who don't run
Vault.

### What envelope encryption looks like here

```
                                  ┌────────────────────┐
        secret (TOTP seed or      │                    │
        token secret)             │   per-secret DEK   │
              │                   │   (32 random       │
              │                   │    bytes)          │
              ▼                   │                    │
        AES-256-GCM ─────────►  ciphertext   ───┐      │
              ▲                                  │     │
              │                                  │     │
              └──────────── DEK ─────────────────┘     │
                                                       │
                          ┌────────────────────────────┘
                          ▼
                ┌─────────────────────┐
                │  KEK (lives in KMS) │
                │  Vault Transit /    │
                │  AWS KMS /          │
                │  Azure Key Vault    │
                └─────────────────────┘
                          │
                          ▼
                 wrapped DEK (encrypted)
```

Stored per row: `ciphertext`, `nonce`, `wrapped_dek`, `key_id`,
`algorithm`. The portal never holds the KEK material — it sends
the DEK to KMS for wrap/unwrap on each use.

### Why per-secret DEK (not a column-wide key)

- Per-secret keys make compromise of one secret blast-radius-bounded.
- Key rotation is a re-wrap of the DEKs, not a re-encrypt of every row.
- Common pattern. Both Vault Transit and AWS KMS document it explicitly.

## Implementation outline

### New module — `api/src/core/secret_encryption.py`

```
class KeyProvider(Protocol):
    async def wrap(self, dek: bytes) -> WrappedKey: ...
    async def unwrap(self, wrapped: WrappedKey) -> bytes: ...
    async def current_key_id(self) -> str: ...

class VaultTransitKeyProvider(KeyProvider): ...   # primary
class AwsKmsKeyProvider(KeyProvider): ...         # for AWS-native
class LocalSealedKeyProvider(KeyProvider): ...    # dev / single-host
```

```
async def encrypt(provider: KeyProvider, plaintext: bytes) -> EncryptedSecret:
    """One call per use site. Generates a DEK, encrypts with AES-256-GCM,
    wraps the DEK with the KEK."""

async def decrypt(provider: KeyProvider, encrypted: EncryptedSecret) -> bytes:
    """Unwraps the DEK via KMS, decrypts the ciphertext."""
```

### Schema changes — migration 014

Add new columns to both tables; keep the existing plaintext columns
populated during transition so a rollback is possible:

```sql
ALTER TABLE tenant_tokens
    ADD COLUMN token_secret_envelope BYTEA,
    ADD COLUMN token_secret_envelope_meta JSONB;

ALTER TABLE tenant_user_mfa_factors
    ADD COLUMN totp_secret_envelope BYTEA,
    ADD COLUMN totp_secret_envelope_meta JSONB;
```

`envelope_meta` carries `{nonce, wrapped_dek, key_id, algorithm}`.
The bytea column is the ciphertext.

### Call-site changes

All call sites that previously read `*_plaintext` go through
`decrypt(provider, ...)` instead. There are two: TOTP verification
in `me_mfa.py` and tenant-token outbound use in
`feeds/inventory_puller.py`.

All call sites that previously *wrote* the plaintext go through
`encrypt(provider, ...)`: `tenants.py` (token creation) and `me_mfa.py`
(TOTP setup).

### Migration

Three phases over three releases:

| Release | What changes | Reversible? |
|---------|-------------|-------------|
| N | Add envelope columns. New writes populate BOTH plaintext + envelope. Reads still prefer plaintext. | Yes — drop new columns |
| N+1 | Reads prefer envelope, fall back to plaintext if NULL. A one-shot backfill script encrypts existing plaintext rows. | Yes — flip read order back |
| N+2 | Drop the plaintext columns. | No |

The phasing matters because envelope decryption depends on KMS
availability. The phase-N rollout doesn't take a hard dependency on
KMS; phase N+1 introduces it; phase N+2 makes it required.

## Open questions

1. **Primary KMS backend.** Vault Transit aligns with AAC's existing
   posture (every customer already runs Vault for compliance). AWS
   KMS is the default for AWS-native customers. Recommendation:
   Vault Transit as primary, AWS KMS as a documented second.
2. **KMS unavailability behavior.** Two options:
   - Fail closed: TOTP verification returns 503, bridge tokens unusable.
   - Fail with audit: log + accept the request, emit a security event.
   Recommendation: fail closed. A 503 with retry is acceptable; a
   silent fallback to "we couldn't decrypt the secret, allow anyway"
   is not.
3. **Key rotation cadence.** Vault Transit supports automatic key
   versioning; new writes use the new version, reads work against
   any version still loaded. Recommendation: 90-day rotation,
   automatic; no per-row re-encryption needed for rotation alone.
4. **Local-dev backend.** What does an engineer running the portal
   locally use when there's no KMS? Options:
   - `LocalSealedKeyProvider` with a file-on-disk KEK (sealed with the
     portal `SECRET_KEY`). Not production-safe; clearly labeled.
   - Refuse to start without KMS. Forces every dev to run Vault dev
     server, which is operational friction.
   Recommendation: `LocalSealedKeyProvider` for dev, with a startup
   warning if it's active in a non-`debug` config.

## Out of scope

- Encrypting OTHER columns (e.g., `ir_json` policy text). The
  data-classification work to decide what else qualifies as a
  "secret" is a separate conversation.
- Field-level encryption for compliance evidence (`compliance_results`
  in the read-only DB). That database is the customer's own; the
  portal doesn't write to it.
- Rotating the portal's `SECRET_KEY` itself.

## Acceptance criteria for the implementation PRs

- All four existing call sites use `encrypt()` / `decrypt()` through
  the provider interface.
- A new integration test exercises the round-trip for both columns
  with `LocalSealedKeyProvider` (the only one we can run in CI).
- The phase-N backfill script is idempotent — running it twice
  yields the same result.
- Documentation includes a runbook for "the KMS is down right now" —
  what oncall does, what the user sees.

## Implementation effort

- Module + KMS interface + Vault provider: 1 day
- Schema migration + backfill script: half day
- Call-site rewrites + tests: half day
- AWS KMS provider (when needed): half day

Roughly 2.5 engineering days for phases N + N+1. Phase N+2 (drop
the plaintext columns) is a separate small PR once we've confirmed
no rollback is needed.
