import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { userPasswordResetConfirm } from "../lib/api";
import { extractErr } from "../lib/utils";

/**
 * Redeems an operator-issued password-reset token.
 *
 * Operator runs POST /admin/v1/tenants/{tid}/users/{uid}/issue-password-reset
 * which returns a one-time reset_token. They hand it OOB to the user;
 * the user hits this page, sets a new password, and is bounced to the
 * login page to sign in fresh.
 *
 * Either accepts the token via a `?token=` query param (deep link from
 * the operator's hand-off email) or via a paste field. The query-param
 * path lets operators send `https://portal.example.com/portal/reset-password?token=…`
 * directly.
 */
export default function PortalResetPasswordPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [token, setToken] = useState(params.get("token") ?? "");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    if (pw !== pw2) {
      setErr("Passwords don't match.");
      return;
    }
    setBusy(true);
    try {
      await userPasswordResetConfirm({
        reset_token: token.trim(),
        new_password: pw,
      });
      setDone(true);
      // Give the user a beat to see the success state before bounce.
      setTimeout(() => navigate("/portal/login", { replace: true }), 1500);
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
            Set your password
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Paste the reset token your operator sent you, then choose a new
            password.
          </p>
        </div>

        {done ? (
          <div className="text-sm text-emerald-600">
            Password set. Redirecting to sign-in…
          </div>
        ) : (
          <>
            <div>
              <label className="label">Reset token</label>
              <input
                className="input font-mono text-xs"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                required
              />
            </div>

            <div>
              <label className="label">New password</label>
              <input
                className="input"
                type="password"
                autoComplete="new-password"
                value={pw}
                onChange={(e) => setPw(e.target.value)}
                required
                minLength={12}
              />
              <p className="text-xs text-slate-500 mt-1">
                At least 12 characters, with three of: lowercase, uppercase,
                digit, symbol.
              </p>
            </div>

            <div>
              <label className="label">Confirm new password</label>
              <input
                className="input"
                type="password"
                autoComplete="new-password"
                value={pw2}
                onChange={(e) => setPw2(e.target.value)}
                required
              />
            </div>

            {err ? <div className="text-sm text-red-600">{err}</div> : null}

            <button className="btn-primary w-full" type="submit" disabled={busy}>
              {busy ? "Setting password…" : "Set password"}
            </button>
          </>
        )}
      </form>
    </div>
  );
}
