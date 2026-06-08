import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  userHostMappingCreate,
  userHostMappingDelete,
  userHostMappingsList,
} from "../lib/api";
import { extractErr } from "../lib/utils";
import type { HostMapping } from "../types/host-mapping";

/**
 * Host mapping admin (P0-A3).
 *
 * Tenant admins (account_owner role) use this page to add or remove
 * which hostnames their tenant sees compliance for. A row with
 * framework=null means "all frameworks for this host"; a specific
 * framework restricts the scope.
 *
 * The backend enforces:
 *   - account_owner role (viewer / editor get 403)
 *   - MFA-verified session (mfa_verified=false → 403)
 *   - Tenant scoping (you can never see / delete another tenant's row)
 *   - Unique (tenant_id, hostname, framework-or-NULL) — duplicates
 *     return 409.
 *
 * Empty list is fine and expected before any mappings are configured.
 * A tenant with no mappings sees an empty compliance dashboard —
 * which IS the correct behavior; we never default to "see everything".
 */
export default function PortalHostMappingsPage() {
  const [rows, setRows] = useState<HostMapping[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const [newHost, setNewHost] = useState("");
  const [newFramework, setNewFramework] = useState("");
  const [creating, setCreating] = useState(false);
  const [createErr, setCreateErr] = useState<string | null>(null);

  // Stable identity so react-hooks/exhaustive-deps is satisfied
  // without re-triggering the effect every render. The eslint rule
  // is enforced with --max-warnings 0 in CI, so a bare
  // `useEffect(reload, [])` would fail the lint job.
  const reload = useCallback(() => {
    setLoading(true);
    setErr(null);
    userHostMappingsList()
      .then(setRows)
      .catch((e) => setErr(extractErr(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newHost.trim()) return;
    setCreating(true);
    setCreateErr(null);
    try {
      await userHostMappingCreate({
        hostname: newHost.trim(),
        framework: newFramework.trim() || null,
      });
      setNewHost("");
      setNewFramework("");
      reload();
    } catch (e) {
      setCreateErr(extractErr(e));
    } finally {
      setCreating(false);
    }
  };

  const onDelete = async (id: string) => {
    if (!window.confirm("Remove this host mapping? The tenant will stop seeing compliance data for this host.")) {
      return;
    }
    try {
      await userHostMappingDelete(id);
      reload();
    } catch (e) {
      setErr(extractErr(e));
    }
  };

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
          <Link
            to="/portal/me"
            className="text-sm text-brand-600 hover:underline"
          >
            ← Home
          </Link>
          <h1 className="text-base font-semibold text-slate-900">
            Host mappings
          </h1>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-4">
        <div className="card p-4 text-sm text-slate-700">
          Add the hostnames your tenant is responsible for. Each mapping
          unlocks compliance read access for that host. Leave framework
          blank to grant access for all frameworks on the host.
        </div>

        <form
          onSubmit={onCreate}
          className="card p-4 space-y-3"
          data-testid="add-mapping-form"
        >
          <div className="flex gap-3 items-end">
            <div className="flex-1">
              <label className="block text-xs font-medium text-slate-600 mb-1">
                Hostname
              </label>
              <input
                type="text"
                value={newHost}
                onChange={(e) => setNewHost(e.target.value)}
                placeholder="host.example"
                className="w-full border border-slate-300 rounded px-2 py-1 text-sm"
                required
                disabled={creating}
              />
            </div>
            <div className="flex-1">
              <label className="block text-xs font-medium text-slate-600 mb-1">
                Framework (optional)
              </label>
              <input
                type="text"
                value={newFramework}
                onChange={(e) => setNewFramework(e.target.value)}
                placeholder="cis_rhel9 (or leave blank for all)"
                className="w-full border border-slate-300 rounded px-2 py-1 text-sm"
                disabled={creating}
              />
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={creating || !newHost.trim()}
            >
              {creating ? "Adding…" : "Add mapping"}
            </button>
          </div>
          {createErr ? (
            <div className="text-sm text-red-600">{createErr}</div>
          ) : null}
        </form>

        {err ? (
          <div className="card p-4 text-sm text-red-600">{err}</div>
        ) : null}

        {loading ? (
          <div className="card p-4 text-sm text-slate-500">Loading…</div>
        ) : rows.length === 0 ? (
          <div className="card p-4 text-sm text-slate-500">
            No host mappings configured yet. Add one above to start scoping
            compliance reads for this tenant.
          </div>
        ) : (
          <div className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-slate-600 text-xs uppercase tracking-wide">
                <tr>
                  <th className="text-left px-4 py-2">Hostname</th>
                  <th className="text-left px-4 py-2">Framework</th>
                  <th className="text-left px-4 py-2">Created</th>
                  <th className="text-right px-4 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr
                    key={row.id}
                    className="border-t border-slate-100 hover:bg-slate-50"
                  >
                    <td className="px-4 py-2 font-mono text-xs">
                      {row.hostname}
                    </td>
                    <td className="px-4 py-2 text-slate-600">
                      {row.framework ?? <em className="text-slate-400">all frameworks</em>}
                    </td>
                    <td className="px-4 py-2 text-slate-500 text-xs">
                      {new Date(row.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <button
                        onClick={() => onDelete(row.id)}
                        className="text-xs text-red-600 hover:underline"
                        data-testid={`delete-${row.id}`}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </main>
    </div>
  );
}
