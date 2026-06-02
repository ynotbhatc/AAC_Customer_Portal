import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { portalWhoAmI } from "../lib/api";
import { setTenantCreds } from "../lib/auth";
import { extractErr } from "../lib/utils";

export default function TenantLoginPage() {
  const navigate = useNavigate();
  const [tenantId, setTenantId] = useState("");
  const [tokenId, setTokenId] = useState("");
  const [tokenSecret, setTokenSecret] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    setTenantCreds({
      tenantId: tenantId.trim(),
      tokenId: tokenId.trim(),
      tokenSecret: tokenSecret.trim(),
    });
    try {
      await portalWhoAmI(tenantId.trim());
      navigate("/my-products", { replace: true });
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
          <h1 className="text-xl font-semibold text-slate-900">Connect to Portal</h1>
          <p className="text-sm text-slate-500 mt-1">
            Paste the credentials your AAC operator gave you to view your CVE
            feed.
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
          <label className="label">Token ID</label>
          <input
            className="input font-mono text-xs"
            placeholder="aac_..."
            value={tokenId}
            onChange={(e) => setTokenId(e.target.value)}
            required
          />
        </div>

        <div>
          <label className="label">Token secret</label>
          <input
            type="password"
            className="input"
            value={tokenSecret}
            onChange={(e) => setTokenSecret(e.target.value)}
            required
          />
        </div>

        {err && (
          <div className="rounded bg-red-50 border border-red-200 text-red-800 text-sm px-3 py-2">
            {err}
          </div>
        )}

        <button
          type="submit"
          className="btn-primary w-full"
          disabled={busy || !tenantId || !tokenId || !tokenSecret}
        >
          {busy ? "Connecting…" : "Connect"}
        </button>

        <div className="text-xs text-slate-500 text-center pt-2">
          <a href="/login" className="underline hover:text-slate-700">
            Operator sign-in →
          </a>
        </div>
      </form>
    </div>
  );
}
