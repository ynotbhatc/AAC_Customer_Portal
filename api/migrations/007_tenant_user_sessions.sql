-- Migration 007 — Tenant-user sessions + password reset (PR 3 of Piece 46)
--
-- Adds the two tables needed for self-service tenant_user authentication:
--
--   tenant_user_sessions          — server-side sessions issued at login
--   tenant_user_password_resets   — single-use tokens for set-password
--
-- Server-side sessions are chosen over stateless JWTs so:
--   - Revocation is instant (set revoked_at — no key rotation flailing).
--   - No JWT signing key to manage / rotate / leak.
--   - Operator action "force-logout a tenant" is one UPDATE statement.
--   - The browser app uses `Authorization: Bearer <session_token>`
--     (header, not cookie) which sidesteps CSRF.
--
-- Tokens are random 256-bit secrets, hashed at rest with bcrypt — the same
-- approach used for tenant_tokens.token_secret_hash in migration 001.
--
-- Both tables CASCADE on tenant_users deletion. They do NOT CASCADE on
-- tenants deletion directly — that's already covered transitively because
-- tenant_users does.

BEGIN;


-- ── tenant_user_sessions ──────────────────────────────────────────────
-- One row per active login. Expires at `expires_at`; the auth code
-- treats any row with revoked_at IS NOT NULL OR expires_at < now() as
-- invalid. Sessions are not rotated automatically — re-login starts a
-- new row, the old one expires.
CREATE TABLE IF NOT EXISTS tenant_user_sessions (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_user_id              uuid        NOT NULL REFERENCES tenant_users(id) ON DELETE CASCADE,
    session_token_hash          text        NOT NULL,
    -- mfa_verified is FALSE between password-step and TOTP-step during
    -- a two-factor login. Endpoints that require MFA must reject
    -- sessions where this is FALSE. TOTP enrollment (PR 4) flips it on.
    mfa_verified                boolean     NOT NULL DEFAULT false,
    issued_at                   timestamptz NOT NULL DEFAULT now(),
    expires_at                  timestamptz NOT NULL,
    last_used_at                timestamptz NOT NULL DEFAULT now(),
    last_used_from_ip           inet,
    user_agent                  text,
    revoked_at                  timestamptz,
    revoked_reason              text
);

CREATE INDEX IF NOT EXISTS idx_tenant_user_sessions_user_active
    ON tenant_user_sessions (tenant_user_id)
    WHERE revoked_at IS NULL;

-- For the auth path's hot lookup: hash → session. We do NOT index on
-- session_token_hash uniqueness because bcrypt salts every hash; the
-- auth code iterates a small list of active rows per user.


-- ── tenant_user_password_resets ───────────────────────────────────────
-- Single-use bearer tokens for the password-reset flow. The operator
-- "issue reset" endpoint creates a row; the user redeems it via the
-- confirm endpoint exactly once. Setting used_at on redeem prevents
-- replay; the confirm endpoint rejects any row where used_at IS NOT NULL
-- OR expires_at < now().
CREATE TABLE IF NOT EXISTS tenant_user_password_resets (
    id                          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_user_id              uuid        NOT NULL REFERENCES tenant_users(id) ON DELETE CASCADE,
    token_hash                  text        NOT NULL,
    issued_at                   timestamptz NOT NULL DEFAULT now(),
    expires_at                  timestamptz NOT NULL,
    used_at                     timestamptz,
    issued_by_admin             boolean     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_password_resets_user_pending
    ON tenant_user_password_resets (tenant_user_id)
    WHERE used_at IS NULL;


COMMIT;
