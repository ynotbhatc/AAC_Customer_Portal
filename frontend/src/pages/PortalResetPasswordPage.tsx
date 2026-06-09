import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { userPasswordResetConfirm } from "../lib/api";
import { extractErr } from "../lib/utils";

/**
 * Redeems an operator-issued password-reset token.
 *
 * Operator runs POST /admin/v1/tenants/{tid}/users/{uid}/issue-password-reset
 * which returns a one-time reset_token. They hand it OOB to the user;
 * the user hits this page, pastes the token, sets a new password, and
 * is bounced to the login page to sign in fresh.
 *
 * Tokens are NEVER accepted from the URL — see
 * docs/security_roadmap.md ("Reset token in URL query param"). URL
 * query strings end up in browser history and any outbound Referer
 * header, which is a credential leak vector. If a legacy email link
 * lands here with `?token=…`, the page strips it before any subrequest
 * fires (history.replaceState) and surfaces a notice asking the user
 * to paste the token from the operator's hand-off message.
 */
export default function PortalResetPasswordPage() {
  const navigate = useNavigate();
  const [token, setToken] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [stripped, setStripped] = useState(false);

  // Strip a legacy `?token=` deep-link from the URL before any
  // subrequest (image, analytics, etc.) leaks it via Referer.
  // useEffect runs synchronously after the first commit, before the
  // browser paints — early enough for typical resources, late enough
  // that we can safely call history.replaceState.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    if (params.has("token")) {
      params.delete("token");
      const qs = params.toString();
      const url =
        window.location.pathname + (qs ? `?${qs}` : "") + window.location.hash;
      window.history.replaceState(null, "", url);
      setStripped(true);
    }
  }, []);

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
            {stripped ? (
              <div className="text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-1.5">
                For security, this page no longer accepts reset tokens from the
                URL. Paste the token your operator sent you below.
              </div>
            ) : null}
            <div>
              <label htmlFor="reset-token" className="label">Reset token</label>
              <input
                id="reset-token"
                className="input font-mono text-xs"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                required
              />
            </div>

            <div>
              <label htmlFor="reset-new-password" className="label">
                New password
              </label>
              <input
                id="reset-new-password"
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
              <label htmlFor="reset-confirm-password" className="label">
                Confirm new password
              </label>
              <input
                id="reset-confirm-password"
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
