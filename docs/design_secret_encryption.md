# Design — Secret Encryption at Rest

**Status:** draft for review — implementation gated on the answers to
the Open Questions section.

**Principle:** AAC is a security product. Credential storage is
load-bearing. The architecture has to be **right** the first time —
no plaintext columns in production. The *operational backend* can
start at OSS / dev tier and graduate to a hardened production
backend when we onboard the first paying customer; the *interface*
that talks to that backend doesn't change.

## Problem

Two columns hold sensitive material in plaintext:

| Table | Column | Why plaintext today | Bridge implication |
|-------|--------|---------------------|---------------------|
| `tenant_tokens` | `token_secret_plaintext` (migration 004:9-24) | Operator must display the secret once at issue time; the on-site AAC bridge stores it in its Ansible Vault for outbound auth back to the portal. `feeds/inventory_puller.py` also reads it. | The portal-side plaintext is one half of the trust chain. The bridge holds the other half in Ansible Vault. Recovering ours recovers the bridge's auth credential. |
| `tenant_user_mfa_factors` | `totp_secret_plaintext` (me_mfa.py:13-20) | TOTP requires the seed itself to compute the current code. Hashing isn't an option for this column. | None — TOTP is browser-side. |

Anyone with read access to the portal's PostgreSQL database can
recover every bridge credential and every TOTP seed. The columns are
explicitly flagged TODO-for-encryption in the migration. The work
has never landed.

## Recommendation

**Envelope encryption with a pluggable Key Encryption Key (KEK)
provider interface.** Ship the proper architecture now; pick the
backend pragmatically based on where we are in the customer journey.

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
                ┌─────────────────────────┐
                │  KEK (lives in KP)      │
                │                         │
                │  Dev / pre-customer:    │
                │    LocalSealed         │ ← ship NOW
                │  Production / customer: │
                │    OpenBao or Vault     │ ← config flip when needed
                │    Community Edition    │
                └─────────────────────────┘
```

Stored per row: `ciphertext`, `nonce`, `wrapped_dek`, `key_id`,
`algorithm`. The portal never holds raw KEK material; the KP unwraps
on demand.

### Backend tiers (pragmatic)

| Backend | Use when | OSS? | Cost | Production-safe? |
|---------|----------|------|------|-------------------|
| `LocalSealedKeyProvider` | Pre-customer, dev environments | Yes (built-in) | Free | No — the KEK is sealed by `SECRET_KEY` which lives in the same env as the DB. A breach of the host gets both. |
| **`OpenBaoKeyProvider`** | First paying customer onward | **Yes — MPL-2.0** ([OpenBao](https://openbao.org/)) | Free | Yes |
| `VaultTransitKeyProvider` | Customer already runs Vault Community Edition (or Enterprise) | Yes — MPL-2.0 (Community) | Free for Community | Yes |
| `AwsKmsKeyProvider` | AWS-native customer asks for it | No (proprietary) | Per-request | Yes |
| `AzureKeyVaultKeyProvider` | Azure-native customer asks for it | No (proprietary) | Per-request | Yes |

**Primary recommendation: OpenBao when we have customers.** OpenBao is
the Linux Foundation fork of HashiCorp Vault that stayed under MPL-2.0
when Vault switched to BUSL. Same wire format as Vault, drop-in for
the Transit secrets engine, no commercial licensing exposure as we
scale. If a customer specifically wants Vault Community or Enterprise
that interoperates 1:1 with the same provider code — just point the
`vault_addr` at theirs.

**Today: `LocalSealedKeyProvider`.** The KEK is generated on first
start, sealed by `SECRET_KEY`, stored at `var/secrets/kek.sealed`. It
makes the encryption architecture real (call sites round-trip through
the provider; the schema carries ciphertext + envelope metadata; key
rotation is implemented) without taking a dependency on standing up
OpenBao before we have customers. **The unfortunate truth: this is
"better than plaintext" but does not pass a customer audit.** It's a
documented stopgap.

### Why per-secret DEK (not a column-wide key)

- A single compromise is blast-radius bounded to one row.
- Rotation is a re-wrap of the affected DEKs, not a re-encrypt of
  every row.
- Standard pattern documented by both Vault Transit and AWS KMS.

## Implementation outline

### New module — `api/src/core/secret_encryption.py`

```
class KeyProvider(Protocol):
    async def wrap(self, dek: bytes) -> WrappedKey: ...
    async def unwrap(self, wrapped: WrappedKey) -> bytes: ...
    async def current_key_id(self) -> str: ...

class LocalSealedKeyProvider(KeyProvider): ...    # ship now
class OpenBaoKeyProvider(KeyProvider): ...        # add when customers
class VaultTransitKeyProvider(KeyProvider): ...   # same wire as OpenBao
class AwsKmsKeyProvider(KeyProvider): ...         # opt-in per customer
```

```
async def encrypt(provider, plaintext) -> EncryptedSecret:
    """Generate a DEK, encrypt with AES-256-GCM, wrap the DEK
    via the KP."""

async def decrypt(provider, encrypted) -> bytes:
    """Unwrap the DEK via KP, decrypt the ciphertext."""
```

`KEK_PROVIDER` config var picks the implementation. Default
`local_sealed` for dev; production deployments set it to
`openbao` / `vault_transit` and add the connection settings.

### Schema changes — migration 014

Add new columns; keep the existing plaintext columns through the
transition for rollback safety:

```sql
ALTER TABLE tenant_tokens
    ADD COLUMN token_secret_envelope BYTEA,
    ADD COLUMN token_secret_envelope_meta JSONB;

ALTER TABLE tenant_user_mfa_factors
    ADD COLUMN totp_secret_envelope BYTEA,
    ADD COLUMN totp_secret_envelope_meta JSONB;
```

`envelope_meta` carries `{nonce, wrapped_dek, key_id, algorithm}`.

### Call-site changes

- `me_mfa.py` writes TOTP secret via `encrypt(...)`; verifies by
  `decrypt(...)` + `pyotp.verify(...)`.
- `tenants.py` writes new tenant token secrets via `encrypt(...)`.
- `feeds/inventory_puller.py` decrypts at use time.

### Migration phases

| Release | What changes | Reversible? |
|---------|-------------|-------------|
| N | Add envelope columns. New writes populate BOTH plaintext + envelope. Reads still prefer plaintext. | Yes — drop columns |
| N+1 | Reads prefer envelope, fall back to plaintext if NULL. Backfill script encrypts existing rows. | Yes — flip read order back |
| N+2 | Drop plaintext columns. | No |

Phase N is risk-free. Phase N+1 introduces the KP dependency. Phase
N+2 is the cleanup that locks in the new world.

### AAC bridge interaction

The portal-side tenant token secret is one end of an M2M trust chain
with the on-site AAC bridge:

- **Portal** issues a token → operator copies the plaintext once →
  bridge stores it in **Ansible Vault on-site** (encrypted at rest
  by the bridge's vault password).
- **Bridge** authenticates back to the portal using that token.
- **Portal** uses the SAME plaintext for outbound calls (today) via
  `inventory_puller.py`.

After the encryption work lands:
- The portal stores the secret as `ciphertext` + envelope metadata.
- At issue time the portal returns the plaintext exactly once
  (current behaviour preserved) so the operator can paste it into
  the AAC bridge's Ansible Vault.
- For outbound calls (`inventory_puller.py`), the portal decrypts
  on demand via the KP.
- **The bridge side is unchanged.** Ansible Vault keeps its own
  copy. The portal's encryption-at-rest is independent of how the
  bridge stores its half — neither side trusts the other to hold
  the secret correctly.

## Open questions

1. **Are we OK shipping `LocalSealedKeyProvider` to pre-customer
   environments?** It's "better than plaintext" but the KEK
   ultimately depends on `SECRET_KEY` being safe — a full-host
   compromise gets both. The alternative is to stand up OpenBao
   in dev now and never use the local backend. Trade-off: ops
   complexity vs purity. **Recommendation: yes ship local; document
   it clearly; mandatory swap to OpenBao before first customer onboards.**
2. **OpenBao vs Vault Community Edition for first customer.**
   Functionally equivalent. OpenBao has zero commercial licensing
   risk; Vault Community is what customers may already run. The
   provider code is the same either way (same Transit API).
   **Recommendation: OpenBao for our hosted deployments; Vault
   Community when a customer asks because they already run Vault.**
3. **KP-unavailable behavior.** Two options:
   - Fail closed: TOTP verification returns 503; bridge tokens
     unusable. Acceptable downtime; obvious failure mode.
   - Fail with audit: log a security event, refuse the request.
   **Recommendation: fail closed. A 503 with retry is acceptable;
   any "we couldn't decrypt, allow anyway" path is unacceptable for
   a security product.**
4. **Key rotation cadence for production.** Vault Transit / OpenBao
   support automatic key versioning; new writes use the new
   version, reads work against any version still loaded.
   **Recommendation: 90-day rotation, automatic; no per-row
   re-encryption needed for rotation alone.**

## Out of scope

- Encrypting OTHER columns (e.g., `ir_json` policy text). The
  data-classification work is a separate conversation.
- Field-level encryption for compliance evidence
  (`compliance_results` in the read-only DB). That database is the
  customer's own; the portal doesn't write to it.
- Rotating the portal's `SECRET_KEY` itself.
- AAC bridge-side Ansible Vault management. The bridge already has
  its own credential lifecycle; we're not changing it.

## Acceptance criteria for the implementation PRs

- All four existing call sites use `encrypt()` / `decrypt()` through
  the provider interface.
- A new integration test exercises the round-trip for both columns
  with `LocalSealedKeyProvider` (the only one we can run in CI).
- An additional integration test (gated on
  `OPENBAO_ADDR` env) exercises the round-trip against a live
  OpenBao instance — same call sites, same assertions.
- The phase-N backfill script is idempotent.
- Documentation includes a runbook for "the KP is down right now" —
  what oncall does, what the user sees.
- `docs/security_roadmap.md` is updated: the `LocalSealedKeyProvider`
  entry moves from "in place but needs upgrade" to "deprecated; OpenBao
  is the production path" once OpenBao integration lands.

## Implementation effort

- Module + KP interface + `LocalSealedKeyProvider` + tests: 1 day
- Schema migration + backfill script: half day
- Call-site rewrites: half day
- `OpenBaoKeyProvider` implementation + smoke test: half day

Total ~2.5 engineering days. Adding `AwsKmsKeyProvider` later is a
half day per backend; the interface stays the same.
