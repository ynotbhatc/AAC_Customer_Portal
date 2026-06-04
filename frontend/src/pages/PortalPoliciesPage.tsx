import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { userPoliciesList } from "../lib/api";
import { extractErr } from "../lib/utils";
import type {
  CustomerPolicySummary,
  PolicyStatus,
} from "../types/policy";

/**
 * Tenant-user list of customer_policies. Two filter dropdowns
 * (status, framework_bucket) and a "Upload a new policy" CTA into
 * the Path A flow. Path B fork-and-tweak lives on a separate page
 * landing in a follow-up PR.
 */
export default function PortalPoliciesPage() {
  const navigate = useNavigate();
  const [policies, setPolicies] = useState<CustomerPolicySummary[]>([]);
  const [statusFilter, setStatusFilter] = useState<PolicyStatus | "">("");
  const [bucketFilter, setBucketFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = () => {
    setBusy(true);
    setErr(null);
    userPoliciesList({
      framework_bucket: bucketFilter || undefined,
      status: statusFilter || undefined,
    })
      .then(setPolicies)
      .catch((e) => setErr(extractErr(e)))
      .finally(() => setBusy(false));
  };

  useEffect(() => {
    load();
    // Re-run when filters change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter, bucketFilter]);

  const buckets = Array.from(new Set(policies.map((p) => p.framework_bucket))).sort();

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link
              to="/portal/me"
              className="text-sm text-brand-600 hover:underline"
            >
              ← Home
            </Link>
            <h1 className="text-base font-semibold text-slate-900">
              Policies
            </h1>
          </div>
          <button
            type="button"
            className="btn-primary text-sm"
            onClick={() => navigate("/portal/policies/upload")}
          >
            Upload a policy
          </button>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6 space-y-4">
        <div className="card p-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="label">Status</label>
              <select
                className="input"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as PolicyStatus | "")}
              >
                <option value="">All</option>
                <option value="draft">Draft</option>
                <option value="in_review">In review</option>
                <option value="published">Published</option>
                <option value="archived">Archived</option>
              </select>
            </div>
            <div>
              <label className="label">Framework bucket</label>
              <select
                className="input"
                value={bucketFilter}
                onChange={(e) => setBucketFilter(e.target.value)}
              >
                <option value="">All</option>
                {buckets.map((b) => (
                  <option key={b} value={b}>
                    {b}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-end">
              <button
                type="button"
                className="btn-secondary text-sm"
                onClick={load}
                disabled={busy}
              >
                {busy ? "Loading…" : "Refresh"}
              </button>
            </div>
          </div>
        </div>

        {err ? (
          <div className="card p-4 text-sm text-red-600">{err}</div>
        ) : null}

        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-600">
              <tr>
                <th className="text-left px-4 py-2 font-medium">Name</th>
                <th className="text-left px-4 py-2 font-medium">Framework</th>
                <th className="text-left px-4 py-2 font-medium">Source</th>
                <th className="text-left px-4 py-2 font-medium">Version</th>
                <th className="text-left px-4 py-2 font-medium">Status</th>
                <th className="text-left px-4 py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {policies.length === 0 && !busy ? (
                <tr>
                  <td
                    colSpan={6}
                    className="px-4 py-6 text-center text-slate-500"
                  >
                    No policies yet. Upload one to get started.
                  </td>
                </tr>
              ) : null}
              {policies.map((p) => (
                <tr
                  key={p.id}
                  className="border-t border-slate-100 hover:bg-slate-50 cursor-pointer"
                  onClick={() => navigate(`/portal/policies/${p.id}`)}
                >
                  <td className="px-4 py-2 font-medium text-slate-900">
                    {p.name}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-700">
                    {p.framework_bucket}
                  </td>
                  <td className="px-4 py-2 text-slate-700">
                    {p.policy_source.replace("_", " ")}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-700">
                    {p.version_semver}
                  </td>
                  <td className="px-4 py-2">
                    <StatusBadge status={p.status} />
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-500">
                    {new Date(p.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}

function StatusBadge({ status }: { status: PolicyStatus }) {
  const styles: Record<PolicyStatus, string> = {
    draft: "bg-slate-100 text-slate-700",
    in_review: "bg-amber-100 text-amber-800",
    published: "bg-emerald-100 text-emerald-800",
    archived: "bg-slate-200 text-slate-500",
  };
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${styles[status]}`}
    >
      {status.replace("_", " ")}
    </span>
  );
}
