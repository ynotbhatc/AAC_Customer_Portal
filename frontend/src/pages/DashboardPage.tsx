import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { listFeedRuns, listTenants } from "../lib/api";
import { extractErr, relTime } from "../lib/utils";

export default function DashboardPage() {
  const { data: tenants } = useQuery({
    queryKey: ["tenants"],
    queryFn: () => listTenants(false),
  });

  const { data: runs, error: runsErr } = useQuery({
    queryKey: ["feed-runs", { limit: 5 }],
    queryFn: () => listFeedRuns({ limit: 5 }),
  });

  const active = tenants?.filter((t) => t.status === "active").length ?? 0;
  const pending = tenants?.filter((t) => t.status === "pending").length ?? 0;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-slate-900">Dashboard</h1>
        <p className="text-sm text-slate-500 mt-1">
          Multi-tenant CVE intelligence — operator overview.
        </p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard label="Tenants (total)" value={tenants?.length ?? "—"} link="/tenants" />
        <StatCard label="Active tenants" value={active} link="/tenants" />
        <StatCard label="Pending tenants" value={pending} link="/tenants" />
      </div>

      <div className="card p-6">
        <h2 className="text-lg font-semibold mb-3">Recent feed runs</h2>
        {runsErr && (
          <div className="text-red-700 text-sm">{extractErr(runsErr)}</div>
        )}
        {runs && runs.length === 0 && (
          <div className="text-slate-500 text-sm">No feed runs yet.</div>
        )}
        {runs && runs.length > 0 && (
          <table className="w-full text-sm">
            <thead className="text-xs uppercase text-slate-500">
              <tr>
                <th className="text-left py-2">Source</th>
                <th className="text-left py-2">Started</th>
                <th className="text-left py-2">Status</th>
                <th className="text-right py-2">New / updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {runs.map((r) => (
                <tr key={r.id}>
                  <td className="py-2 font-medium">{r.source}</td>
                  <td className="py-2 text-slate-500">{relTime(r.started_at)}</td>
                  <td className="py-2">{r.status}</td>
                  <td className="py-2 text-right text-slate-700">
                    {r.new_count ?? 0} / {r.updated_count ?? 0}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <div className="pt-3">
          <Link to="/feeds" className="text-sm text-brand-600 hover:underline">
            View all feed runs →
          </Link>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  link,
}: {
  label: string;
  value: number | string;
  link: string;
}) {
  return (
    <Link
      to={link}
      className="card p-5 hover:border-brand-500 transition-colors block"
    >
      <div className="text-sm text-slate-500">{label}</div>
      <div className="text-3xl font-semibold text-slate-900 mt-1">{value}</div>
    </Link>
  );
}
