import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { userLogout, userLogoutAll, userMe } from "../lib/api";
import { clearUserSession, getUserSession } from "../lib/auth";
import { extractErr } from "../lib/utils";
import type { MeResponse } from "../types/user";

/**
 * Tenant-user landing page after sign-in. Shows identity, MFA status,
 * and the logout / logout-all controls. Future PRs add navigation to
 * the policy ingestion pages (upload, library browse, review,
 * publish, bundles).
 *
 * If the session was revoked server-side, the api interceptor in
 * lib/api.ts catches the 401 and bounces to /portal/login. This page
 * doesn't need its own retry logic.
 */
export default function PortalHomePage() {
  const navigate = useNavigate();
  const session = getUserSession();
  const [me, setMe] = useState<MeResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!session) {
      navigate("/portal/login", { replace: true });
      return;
    }
    userMe()
      .then(setMe)
      .catch((e) => setErr(extractErr(e)));
  }, [navigate, session]);

  const onLogout = async () => {
    setBusy(true);
    try {
      await userLogout();
    } catch {
      // Ignore — server may have already revoked the session.
    } finally {
      clearUserSession();
      navigate("/portal/login", { replace: true });
    }
  };

  const onLogoutAll = async () => {
    if (
      !window.confirm(
        "Sign out of EVERY device for this user? Use this if you suspect " +
          "your account has been compromised."
      )
    ) {
      return;
    }
    setBusy(true);
    try {
      await userLogoutAll();
    } catch {
      // Ignore.
    } finally {
      clearUserSession();
      navigate("/portal/login", { replace: true });
    }
  };

  if (!session) return null;

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
          <h1 className="text-base font-semibold text-slate-900">
            AAC Compliance Portal
          </h1>
          <div className="flex items-center gap-3">
            <span className="text-sm text-slate-600">{session.email}</span>
            <button
              type="button"
              className="btn-secondary text-sm"
              onClick={onLogout}
              disabled={busy}
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8 space-y-6">
        {err ? (
          <div className="card p-4 text-sm text-red-600">{err}</div>
        ) : null}

        <section className="card p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-4">
            Your account
          </h2>
          {me ? (
            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
              <div>
                <dt className="text-slate-500">Email</dt>
                <dd className="text-slate-900">{me.email}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Role</dt>
                <dd className="text-slate-900 font-mono text-xs">{me.role}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Display name</dt>
                <dd className="text-slate-900">
                  {me.display_name ?? <span className="text-slate-400">—</span>}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Tenant ID</dt>
                <dd className="text-slate-900 font-mono text-xs break-all">
                  {me.tenant_id}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">MFA required</dt>
                <dd className="text-slate-900">
                  {me.mfa_required ? "Yes" : "No"}
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">MFA verified this session</dt>
                <dd className="text-slate-900">
                  {me.mfa_verified ? (
                    <span className="text-emerald-600">Yes</span>
                  ) : (
                    <span className="text-amber-600">Not yet</span>
                  )}
                </dd>
              </div>
            </dl>
          ) : (
            <p className="text-sm text-slate-500">Loading…</p>
          )}
        </section>

        {me && me.mfa_required && !me.mfa_verified ? (
          <section className="card p-6 border-l-4 border-amber-500">
            <h2 className="text-base font-semibold text-slate-900 mb-2">
              {me.mfa_enrolled
                ? "Verify your second factor"
                : "Set up two-factor authentication"}
            </h2>
            <p className="text-sm text-slate-500 mb-4">
              {me.mfa_enrolled
                ? "Your session hasn't completed MFA yet. Enter a TOTP or backup code to unlock policy writes (upload, publish, bundle build)."
                : "Your account requires MFA before you can publish policies or build bundles. Enrolling takes ~30 seconds."}
            </p>
            <button
              type="button"
              className="btn-primary text-sm"
              onClick={() =>
                navigate(me.mfa_enrolled ? "/portal/mfa/verify" : "/portal/mfa/setup")
              }
            >
              {me.mfa_enrolled ? "Verify now" : "Enroll TOTP"}
            </button>
          </section>
        ) : null}

        <section className="card p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-2">
            Policy ingestion
          </h2>
          <p className="text-sm text-slate-500 mb-4">
            Upload a written policy or fork a standard library file to start
            building your tenant's Rego bundle. Both paths converge on the
            same review + publish workflow.
          </p>
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              className="btn-primary text-sm"
              onClick={() => navigate("/portal/policies")}
            >
              Open policies
            </button>
            <button
              type="button"
              className="btn-secondary text-sm"
              onClick={() => navigate("/portal/policies/upload")}
              disabled={me ? me.mfa_required && !me.mfa_verified : false}
            >
              Upload a policy
            </button>
            <button
              type="button"
              className="btn-secondary text-sm"
              onClick={() => navigate("/portal/library")}
            >
              Browse standard library
            </button>
            <button
              type="button"
              className="btn-secondary text-sm"
              onClick={() => navigate("/portal/bundles")}
            >
              Bundles
            </button>
            <button
              type="button"
              className="btn-secondary text-sm"
              onClick={() => navigate("/portal/baselines")}
            >
              Baselines
            </button>
            {me && me.mfa_required && !me.mfa_verified ? (
              <span className="text-xs text-amber-700">
                MFA verification required for upload + fork.
              </span>
            ) : null}
          </div>
        </section>

        <section className="card p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-2">
            Security
          </h2>
          <p className="text-sm text-slate-500 mb-4">
            If you suspect your account has been compromised, sign out of every
            device and ask your operator to issue a password reset.
          </p>
          <button
            type="button"
            className="btn-danger text-sm"
            onClick={onLogoutAll}
            disabled={busy}
          >
            Sign out of all devices
          </button>
        </section>
      </main>
    </div>
  );
}
