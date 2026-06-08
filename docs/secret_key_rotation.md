# SECRET_KEY Rotation Runbook

**Version:** v1.0
**Owner:** Portal operations

## What it is

`SECRET_KEY` is the master signing secret read by `api/src/core/config.py`. It signs anything the portal issues that needs tamper-evidence — today that includes:

- Session token hashes (indirectly, via the per-session bcrypt'd token)
- Future: any signed cookies, CSRF tokens, password-reset tokens that derive from this key

`SECRET_KEY` has **no default** in `config.py` — Pydantic raises at startup if it's unset. Every environment must explicitly provide it.

## When to rotate

Rotate the key on any of:

| Trigger | Window |
|---|---|
| Suspected compromise (leak in logs, dev shared it, etc.) | Immediately |
| Departed operator who had access to the key | Same day |
| Scheduled rotation cadence (recommended: every 180 days) | Calendar-driven |
| Major release that changes session-signing semantics | At deploy |
| Compliance requirement (some FedRAMP / SOC 2 profiles require periodic key rotation) | Per the requirement |

## What a rotation does

**Important:** rotating `SECRET_KEY` invalidates every active session. Every logged-in tenant user gets bounced to the login page on their next request. This is by design — if the key is rotated because of a compromise, you WANT every existing session killed.

Plan the rotation window during low-traffic hours and notify customers ahead of time if rotating proactively.

## Procedure

### 1. Generate the new key

```bash
# 64 bytes of crypto random, base64-encoded — safe for env vars
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

Capture the output. This is the new `SECRET_KEY`. Do **not** commit it to git, paste it into a chat, or store it in a wiki. Use your secrets store (e.g., Hashicorp Vault, AWS Secrets Manager, or the AAP Vault credential per environment).

### 2. Stage the new key in the secrets store

| Env | Secrets store location |
|---|---|
| Lab | `ansible/vars/vault_secrets.yml` (key: `vault_portal_secret_key`) |
| Demo (RHPDS) | per-cluster `vault_secrets.<demo-slug>.yml` |
| Customer | customer-provided secret manager — never our vault |

Stage the new value WITHOUT removing the old yet. The two values coexist for a brief window so the deploy step (next) can pick up the new one cleanly.

### 3. Restart the API container with the new value

```bash
# Lab — the standard deploy flow
podman-compose -f deploy/podman/docker-compose.yml down api
SECRET_KEY="<new-value>" podman-compose -f deploy/podman/docker-compose.yml up -d api

# Demo / customer — run via your usual deploy automation; the
# SECRET_KEY env var must be set on the container at boot
```

On boot, the API process reads `SECRET_KEY` from the environment. If it's missing, Pydantic raises and the container fails to start — that's the right behavior (don't run unauthed).

### 4. Verify

```bash
# /health probes the DB pools but doesn't expose key state.
# To verify the API actually picked up the new key:
#   - tail the logs; you should see the lifespan startup banner
#   - hit any authenticated endpoint with an OLD bearer token — it
#     should reject with 401 invalid session
curl -s -o /dev/null -w "%{http_code}\n" http://<portal-host>:3000/api/me \
    -H "Authorization: Bearer <session-from-before-rotation>"
# Expected: 401
```

### 5. Remove the old key from the secrets store

Once the API is confirmed running on the new key (step 4 passes), delete the old value from the secrets store entry.

### 6. Audit

Write an audit entry to `system_audit_log` (it's append-only; just an `INSERT` is fine):

```sql
INSERT INTO system_audit_log (
    method, path, status_code, resource_type, resource_id, details
) VALUES (
    'OPS', 'secret_key_rotation', 200, 'config', 'SECRET_KEY',
    jsonb_build_object('rotated_by', '<operator-email>', 'reason', '<scheduled|compromise|other>')
);
```

This puts the rotation event into the same trail as every API mutation so a compliance auditor sees the lifecycle.

## What gets invalidated

- ✅ All active `tenant_user_sessions` rows (the token-hash check still works, but client-stored session tokens encode no key-bound material — clients will need to re-login because session validation paths will start trusting the new key for new sessions)

Actually — **in the current implementation, sessions are stored as bcrypt hashes of random secrets and do NOT depend on `SECRET_KEY`**. So existing sessions remain technically valid after rotation. This is a known gap; tracked as P0-D3 (binding session validation to the current key).

For a "hard rotation" that actually kills every session today, follow up the steps above with:

```sql
UPDATE tenant_user_sessions
   SET revoked_at = now(),
       revoked_reason = 'SECRET_KEY rotation <date>'
 WHERE revoked_at IS NULL;
```

This is what you'd run for a compromise-driven rotation.

## Follow-on hardening (out of scope for this rotation)

- **P0-D2 — Remove `'unsafe-inline'` from CSP `style-src`**: PatternFly + Vite inject inline styles. Need to either enumerate the SHA-256 hashes of every legitimate inline style block (build-time extraction; nginx config bumps per release), OR move to per-request nonces via nginx scripting / a tiny FastAPI-side CSP middleware that inlines a nonce into both the response header and the served HTML. Either approach is its own PR.
- **P0-D3 — Bind session validation to `SECRET_KEY`**: prepend the bcrypt input with the current key so rotation kills sessions automatically without needing the manual UPDATE above.
- **P0-D4 — Move secrets to HashiCorp Vault**: today secrets live in plaintext YAML at `ansible/vars/vault_secrets.yml`. Vault gives proper audit + lease lifecycle. Effort: moderate; ties into the per-customer credential management work.

## Pointers

- `api/src/core/config.py:39` — where `SECRET_KEY` is required
- `api/src/core/sessions.py` — session management (token mint, validation, revoke)
- `docs/design_secret_encryption.md` — broader secret-management design context
