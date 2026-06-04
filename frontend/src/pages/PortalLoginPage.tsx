import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { userLogin } from "../lib/api";
import { extractErr } from "../lib/utils";

/**
 * Tenant-user login for the policy ingestion portal.
 *
 * Distinct from /my-products/login (M2M tenant_token) and /login
 * (operator admin). Submits email + password + tenant_id against
 * POST /api/portal/v1/auth/login and stores the session_token via
 * setUserSession.
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
      await userLogin({
        tenant_id: tenantId.trim(),
        email: email.trim(),
        password,
      });
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
