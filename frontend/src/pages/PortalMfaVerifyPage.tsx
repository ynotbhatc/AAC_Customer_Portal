import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { userTotpVerify } from "../lib/api";
import { extractErr } from "../lib/utils";

/**
 * Login-time TOTP verification.
 *
 * Reached when an mfa_required user signs in: their session is issued
 * with mfa_verified=false, /portal/me sees it and bounces here. The
 * user enters a 6-digit code (TOTP) OR a backup code; on success the
 * server flips session.mfa_verified=true and we navigate to the home
 * page. Subsequent MFA-gated endpoints (policy uploads, publish,
 * bundle build) now work.
 *
 * No re-fetch of /me is needed — userTotpVerify updates the local
 * UserSession optimistically.
 */
export default function PortalMfaVerifyPage() {
  const navigate = useNavigate();
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      await userTotpVerify({ code: code.trim() });
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
            Two-factor authentication
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Enter the 6-digit code from your authenticator app — or one of
            your one-time backup codes if you've lost the authenticator.
          </p>
        </div>

        <div>
          <label className="label">Code</label>
          <input
            className="input font-mono text-lg tracking-widest text-center"
            inputMode="text"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            required
            autoFocus
            maxLength={64}
          />
          <p className="text-xs text-slate-500 mt-1">
            TOTP codes are 6 digits. Backup codes are longer; either is
            accepted.
          </p>
        </div>

        {err ? <div className="text-sm text-red-600">{err}</div> : null}

        <button
          type="submit"
          className="btn-primary w-full"
          disabled={busy || code.length === 0}
        >
          {busy ? "Verifying…" : "Verify"}
        </button>
      </form>
    </div>
  );
}
