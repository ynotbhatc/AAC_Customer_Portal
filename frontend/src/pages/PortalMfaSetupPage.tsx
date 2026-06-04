import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { userMfaTotpConfirm, userMfaTotpSetup, userTotpVerify } from "../lib/api";
import { extractErr } from "../lib/utils";
import type { TotpSetupResponse } from "../types/user";

/**
 * TOTP enrollment for tenant_users with mfa_required=true.
 *
 * Two-phase flow:
 *
 *   Phase 1 (setup): POST /me/mfa/totp/setup → otpauth_uri + secret.
 *     We show the otpauth:// URI as a clickable link (the OS hands
 *     it to whichever authenticator app the user has registered)
 *     AND the raw base32 secret for paste-into-app fallback.
 *
 *   Phase 2 (confirm): user types the 6-digit code their app shows,
 *     we POST /me/mfa/totp/confirm. On success the server returns 10
 *     one-time backup codes — we show them ONCE.
 *
 *   Phase 3 (verify session): we immediately POST /auth/totp/verify
 *     with the SAME code so the user's current session is flipped to
 *     mfa_verified=true and they don't have to re-enter their code.
 *     If verify fails we still consider enrollment done — the user
 *     just has to verify on next page load.
 */
export default function PortalMfaSetupPage() {
  const navigate = useNavigate();
  const [phase, setPhase] = useState<"setup" | "confirm" | "backup_codes">(
    "setup"
  );
  const [setupData, setSetupData] = useState<TotpSetupResponse | null>(null);
  const [code, setCode] = useState("");
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [acknowledgedBackup, setAcknowledgedBackup] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setBusy(true);
    userMfaTotpSetup()
      .then((d) => {
        setSetupData(d);
        setPhase("confirm");
      })
      .catch((e) => setErr(extractErr(e)))
      .finally(() => setBusy(false));
  }, []);

  const onConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!setupData) return;
    setErr(null);
    setBusy(true);
    try {
      const { backup_codes } = await userMfaTotpConfirm({
        factor_id: setupData.factor_id,
        code: code.trim(),
      });
      setBackupCodes(backup_codes);

      // Best-effort: flip the current session's mfa_verified flag
      // using the same code. Window is brief (~30s) so this should
      // always succeed; if not we just continue — user verifies on
      // the next protected request.
      try {
        await userTotpVerify({ code: code.trim() });
      } catch {
        // ignore
      }

      setPhase("backup_codes");
    } catch (e2) {
      setErr(extractErr(e2));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100">
      <div className="card p-8 w-full max-w-lg space-y-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-900">
            Set up two-factor authentication
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Your account requires a second factor for sensitive operations
            (publishing policies, building bundles).
          </p>
        </div>

        {err ? <div className="text-sm text-red-600">{err}</div> : null}

        {phase === "setup" && busy ? (
          <p className="text-sm text-slate-500">Generating secret…</p>
        ) : null}

        {phase === "confirm" && setupData ? (
          <form onSubmit={onConfirm} className="space-y-4">
            <div>
              <p className="text-sm text-slate-700 mb-2">
                <strong>Step 1.</strong> Open your authenticator app (Google
                Authenticator, 1Password, Authy, …) and add a new account using{" "}
                <a
                  href={setupData.otpauth_uri}
                  className="text-brand-600 hover:underline"
                >
                  this provisioning link
                </a>
                . If your device can't open the link, paste the secret below
                manually.
              </p>
              <div className="text-xs">
                <div className="text-slate-500 mb-1">Secret (base32):</div>
                <code className="block bg-slate-50 border border-slate-200 rounded px-3 py-2 font-mono break-all">
                  {setupData.secret}
                </code>
              </div>
            </div>

            <div>
              <label className="label">
                <strong>Step 2.</strong> Enter the 6-digit code your
                authenticator shows:
              </label>
              <input
                className="input font-mono text-lg tracking-widest text-center"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, ""))}
                required
                autoFocus
              />
            </div>

            <button
              type="submit"
              className="btn-primary w-full"
              disabled={busy || code.length !== 6}
            >
              {busy ? "Confirming…" : "Confirm enrollment"}
            </button>
          </form>
        ) : null}

        {phase === "backup_codes" && backupCodes ? (
          <div className="space-y-4">
            <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
              <strong>Save these backup codes now.</strong> Each one signs you
              in <em>exactly once</em> if you lose your authenticator. We will
              never show them again.
            </div>
            <ul className="grid grid-cols-2 gap-2 font-mono text-sm">
              {backupCodes.map((c) => (
                <li
                  key={c}
                  className="bg-slate-50 border border-slate-200 rounded px-3 py-2"
                >
                  {c}
                </li>
              ))}
            </ul>
            <label className="flex items-center gap-2 text-sm text-slate-700">
              <input
                type="checkbox"
                checked={acknowledgedBackup}
                onChange={(e) => setAcknowledgedBackup(e.target.checked)}
              />
              I've saved these codes in a safe place.
            </label>
            <button
              type="button"
              className="btn-primary w-full"
              disabled={!acknowledgedBackup}
              onClick={() => navigate("/portal/me", { replace: true })}
            >
              Continue to portal
            </button>
          </div>
        ) : null}
      </div>
    </div>
  );
}
