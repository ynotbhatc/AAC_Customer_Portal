import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createTenant, listTenants } from "../lib/api";
import type { TenantCreate, Tier } from "../types/cve";
import { extractErr, relTime, statusColor, tierColor } from "../lib/utils";

export default function TenantsPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data: tenants, isLoading, error } = useQuery({
    queryKey: ["tenants"],
    queryFn: () => listTenants(false),
  });

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Tenants</h1>
          <p className="text-sm text-slate-500 mt-1">
            Customer organizations consuming the CVE feed.
          </p>
        </div>
        <button className="btn-primary" onClick={() => setShowCreate(true)}>
          + New tenant
        </button>
      </header>

      {showCreate && (
        <CreateTenantForm
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            qc.invalidateQueries({ queryKey: ["tenants"] });
            setShowCreate(false);
          }}
        />
      )}

      <div className="card">
        {isLoading && <div className="p-6 text-slate-500">Loading…</div>}
        {error && (
          <div className="p-6 text-red-700">
            Failed to load tenants: {extractErr(error)}
          </div>
        )}
        {tenants && tenants.length === 0 && (
          <div className="p-6 text-slate-500">
            No tenants yet. Create one to get started.
          </div>
        )}
        {tenants && tenants.length > 0 && (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-600 text-xs uppercase">
              <tr>
                <th className="text-left px-4 py-3">Name</th>
                <th className="text-left px-4 py-3">Tier</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-left px-4 py-3">Bridge URL</th>
                <th className="text-left px-4 py-3">Created</th>
                <th></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {tenants.map((t) => (
                <tr key={t.id} className="hover:bg-slate-50">
                  <td className="px-4 py-3">
                    <Link
                      to={`/tenants/${t.id}`}
                      className="font-medium text-slate-900 hover:text-brand-600"
                    >
                      {t.display_name}
                    </Link>
                    {t.contact_email && (
                      <div className="text-xs text-slate-500">{t.contact_email}</div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`badge ${tierColor(t.tier)}`}>{t.tier}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`badge ${statusColor(t.status)}`}>{t.status}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-600 font-mono truncate max-w-xs">
                    {t.aac_bridge_url ?? "—"}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">
                    {relTime(t.created_at)}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Link
                      to={`/tenants/${t.id}`}
                      className="text-xs text-brand-600 hover:underline"
                    >
                      Manage →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function CreateTenantForm({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [form, setForm] = useState<TenantCreate>({
    display_name: "",
    contact_email: "",
    tier: "standard",
    aac_bridge_url: "",
    aac_bridge_verify_ssl: true,
    notes: "",
  });
  const [err, setErr] = useState<string | null>(null);

  const m = useMutation({
    mutationFn: () => {
      const body: TenantCreate = {
        display_name: form.display_name,
        tier: form.tier,
        aac_bridge_verify_ssl: form.aac_bridge_verify_ssl,
        ...(form.contact_email ? { contact_email: form.contact_email } : {}),
        ...(form.aac_bridge_url ? { aac_bridge_url: form.aac_bridge_url } : {}),
        ...(form.notes ? { notes: form.notes } : {}),
      };
      return createTenant(body);
    },
    onSuccess: onCreated,
    onError: (e) => setErr(extractErr(e)),
  });

  return (
    <div className="card p-6">
      <h2 className="text-lg font-semibold mb-4">Create tenant</h2>
      <form
        className="grid grid-cols-1 md:grid-cols-2 gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          setErr(null);
          m.mutate();
        }}
      >
        <div>
          <label className="label">Display name *</label>
          <input
            className="input"
            value={form.display_name}
            onChange={(e) => setForm({ ...form, display_name: e.target.value })}
            required
          />
        </div>

        <div>
          <label className="label">Contact email</label>
          <input
            type="email"
            className="input"
            value={form.contact_email ?? ""}
            onChange={(e) => setForm({ ...form, contact_email: e.target.value })}
          />
        </div>

        <div>
          <label className="label">Tier</label>
          <select
            className="input"
            value={form.tier}
            onChange={(e) => setForm({ ...form, tier: e.target.value as Tier })}
          >
            <option value="free">free</option>
            <option value="standard">standard</option>
            <option value="premium">premium</option>
            <option value="airgapped">airgapped</option>
          </select>
        </div>

        <div>
          <label className="label">AAC bridge URL</label>
          <input
            className="input"
            placeholder="https://aac.customer.example/api/bridge"
            value={form.aac_bridge_url ?? ""}
            onChange={(e) => setForm({ ...form, aac_bridge_url: e.target.value })}
          />
        </div>

        <div className="md:col-span-2 flex items-center gap-2">
          <input
            id="verify_ssl"
            type="checkbox"
            checked={form.aac_bridge_verify_ssl}
            onChange={(e) =>
              setForm({ ...form, aac_bridge_verify_ssl: e.target.checked })
            }
          />
          <label htmlFor="verify_ssl" className="text-sm text-slate-700">
            Verify TLS on bridge URL
          </label>
        </div>

        <div className="md:col-span-2">
          <label className="label">Notes</label>
          <textarea
            className="input"
            rows={2}
            value={form.notes ?? ""}
            onChange={(e) => setForm({ ...form, notes: e.target.value })}
          />
        </div>

        {err && (
          <div className="md:col-span-2 rounded bg-red-50 border border-red-200 text-red-800 text-sm px-3 py-2">
            {err}
          </div>
        )}

        <div className="md:col-span-2 flex justify-end gap-2">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={m.isPending}>
            {m.isPending ? "Creating…" : "Create tenant"}
          </button>
        </div>
      </form>
    </div>
  );
}
