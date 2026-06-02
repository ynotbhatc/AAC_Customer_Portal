import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { adminPing } from "../lib/api";
import { setAdminToken } from "../lib/auth";
import { extractErr } from "../lib/utils";

export default function LoginPage() {
  const navigate = useNavigate();
  const [token, setToken] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    setAdminToken(token.trim());
    try {
      await adminPing();
      navigate("/", { replace: true });
    } catch (e2) {
      setErr(extractErr(e2));
      setAdminToken("");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-100">
      <form
        onSubmit={onSubmit}
        className="card p-8 w-full max-w-md space-y-4"
      >
        <div>
          <h1 className="text-xl font-semibold text-slate-900">
            AAC Operator Console
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Sign in with the portal admin token.
          </p>
        </div>

        <div>
          <label className="label">Admin token</label>
          <input
            type="password"
            className="input"
            placeholder="PORTAL_ADMIN_TOKEN"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoFocus
            required
          />
        </div>

        {err && (
          <div className="rounded bg-red-50 border border-red-200 text-red-800 text-sm px-3 py-2">
            {err}
          </div>
        )}

        <button type="submit" className="btn-primary w-full" disabled={busy || !token}>
          {busy ? "Signing in…" : "Sign in"}
        </button>

        <div className="text-xs text-slate-500 text-center pt-2">
          <a href="/my-products" className="underline hover:text-slate-700">
            Tenant view (My Products) →
          </a>
        </div>
      </form>
    </div>
  );
}
