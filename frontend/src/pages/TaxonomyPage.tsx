import { useQuery } from "@tanstack/react-query";
import { listBuckets, listVendors } from "../lib/api";
import { extractErr } from "../lib/utils";

export default function TaxonomyPage() {
  const { data: buckets, error: bErr } = useQuery({
    queryKey: ["buckets"],
    queryFn: () => listBuckets(),
  });
  const { data: vendors, error: vErr } = useQuery({
    queryKey: ["vendors"],
    queryFn: () => listVendors(),
  });

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">Buckets & Vendors</h1>
        <p className="text-sm text-slate-500 mt-1">
          Taxonomy used to classify CVEs and drive tenant subscriptions.
          Seeded from <code className="text-xs">003a_taxonomy_seed.sql</code>.
        </p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <div className="px-4 py-3 border-b border-slate-200">
            <h2 className="font-semibold">Buckets ({buckets?.length ?? "—"})</h2>
          </div>
          {bErr && (
            <div className="p-4 text-red-700 text-sm">{extractErr(bErr)}</div>
          )}
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-xs uppercase text-slate-600">
              <tr>
                <th className="text-left px-4 py-2">Bucket</th>
                <th className="text-left px-4 py-2">Type</th>
                <th className="text-right px-4 py-2">CVEs</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {buckets?.map((b) => (
                <tr key={b.id}>
                  <td className="px-4 py-2">
                    <div className="font-medium">{b.display_name}</div>
                    <div className="text-xs text-slate-500 font-mono">{b.key}</div>
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-600">{b.bucket_type}</td>
                  <td className="px-4 py-2 text-right">{b.cve_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="card">
          <div className="px-4 py-3 border-b border-slate-200">
            <h2 className="font-semibold">Vendors ({vendors?.length ?? "—"})</h2>
          </div>
          {vErr && (
            <div className="p-4 text-red-700 text-sm">{extractErr(vErr)}</div>
          )}
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-xs uppercase text-slate-600">
              <tr>
                <th className="text-left px-4 py-2">Vendor</th>
                <th className="text-left px-4 py-2">Buckets</th>
                <th className="text-right px-4 py-2">CVEs</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {vendors?.map((v) => (
                <tr key={v.id}>
                  <td className="px-4 py-2">
                    <div className="font-medium">{v.display_name}</div>
                    <div className="text-xs text-slate-500 font-mono">{v.key}</div>
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-600">
                    {(v.buckets ?? []).join(", ") || "—"}
                  </td>
                  <td className="px-4 py-2 text-right">{v.cve_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
