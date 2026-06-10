import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { userLogin, userMfaFactors } from "../lib/api";
import { extractErr } from "../lib/utils";

/**
 * Tenant-user login for the policy ingestion portal.
 *
 * Distinct from /my-products/login (M2M tenant_token) and /login
 * (operator admin). Submits email + password + tenant_id against
 * POST /api/portal/v1/auth/login; the server sets aac_session +
 * aac_csrf cookies (HttpOnly + double-submit). The SPA reads the
 * non-HttpOnly aac_csrf cookie via readCsrfCookie() on subsequent
 * mutations.
 *
 * After login, mfa_required users land on /portal/me; the MFA step
 * (PR 16+) gates write endpoints separately. Read endpoints like
 * /me work immediately.
 */
export default function PortalLoginPage() {
  const navigate = useNavigate();
  const [tenantId, setTenantId] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const session = await userLogin({
        tenant_id: tenantId.trim(),
        email: email.trim(),
        password,
      });

      // MFA-required users: route to the right MFA page.
      //   - Not yet enrolled with TOTP → /portal/mfa/setup
      //   - Enrolled but session not yet verified → /portal/mfa/verify
      // We probe enrollment via /me/mfa/factors instead of /me because
      // /me's mfa_enrolled is on the user row; factors tells us whether
      // a confirmed (non-pending_setup) TOTP exists. That's the
      // distinction that matters for this routing.
      if (session.mfa_required && !session.mfa_verified) {
        try {
          const factors = await userMfaFactors();
          const hasConfirmedTotp = factors.some(
            (f) =>
              f.factor_type === "totp" &&
              f.factor_label !== "pending_setup" &&
              f.revoked_at === null
          );
          navigate(hasConfirmedTotp ? "/portal/mfa/verify" : "/portal/mfa/setup", {
            replace: true,
          });
          return;
        } catch {
          // If we can't fetch factors, fall through to /portal/me; the
          // home page will show the MFA-not-verified warning and the
          // user can navigate to /portal/mfa/setup explicitly.
        }
      }

      navigate("/portal/me", { replace: true });
    } catch (e2) {
      setErr(extractErr(e2));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100">
      <form onSubmit={onSubmit} className="card p-8 w-full max-w-md space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">
            Sign in to AAC Compliance Portal
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Use the credentials your account owner provided. If this is your
            first sign-in, ask your operator for a password-reset link.
          </p>
        </div>

        <div>
          <label className="label">Tenant ID</label>
          <input
            className="input font-mono text-xs"
            placeholder="00000000-0000-0000-0000-000000000000"
            value={tenantId}
            onChange={(e) => setTenantId(e.target.value)}
            required
          />
        </div>

        <div>
          <label className="label">Email</label>
          <input
            className="input"
            type="email"
            autoComplete="username"
            placeholder="you@example.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>

        <div>
          <label className="label">Password</label>
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>

        {err ? <div className="text-sm text-red-600">{err}</div> : null}

        <button className="btn-primary w-full" type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>

        <div className="text-xs text-slate-500 text-center pt-2">
          Have a password-reset link?{" "}
          <a
            href="/portal/reset-password"
            className="text-brand-600 hover:underline"
          >
            Redeem it here
          </a>
          .
        </div>
      </form>
    </div>
  );
}
