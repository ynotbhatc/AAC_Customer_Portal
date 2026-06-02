import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  getCveTags,
  listBuckets,
  listCves,
  listVendors,
  tagBucket,
  tagVendor,
  untagBucket,
  untagVendor,
} from "../lib/api";
import type { Severity } from "../types/cve";
import { extractErr, relTime, severityColor } from "../lib/utils";
import { useMutation, useQueryClient } from "@tanstack/react-query";

export default function CvesPage() {
  const [sev, setSev] = useState<Severity | "">("");
  const [kev, setKev] = useState(false);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const { data, isLoading, error } = useQuery({
    queryKey: ["cves", sev, kev, search],
    queryFn: () =>
      listCves({
        severity: sev || undefined,
        kev_only: kev || undefined,
        search: search || undefined,
        limit: 200,
      }),
  });

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold">CVE browser</h1>
        <p className="text-sm text-slate-500 mt-1">
          Filter the full CVE corpus and tag rows with buckets + vendors.
        </p>
      </header>

      <div className="card p-4 flex flex-wrap gap-3 items-end">
        <div>
          <label className="label">Severity</label>
          <select
            className="input"
            value={sev}
            onChange={(e) => setSev(e.target.value as Severity | "")}
          >
            <option value="">All</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-700 mb-2">
          <input
            type="checkbox"
            checked={kev}
            onChange={(e) => setKev(e.target.checked)}
          />
          KEV only
        </label>
        <div className="flex-1 min-w-[200px]">
          <label className="label">Search (CVE id or description)</label>
          <input
            className="input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="CVE-2024- or 'openssh'"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className={selected ? "lg:col-span-2" : "lg:col-span-3"}>
          <div className="card">
            {isLoading && <div className="p-4 text-slate-500">Loading…</div>}
            {error && (
              <div className="p-4 text-red-700 text-sm">{extractErr(error)}</div>
            )}
            {data && data.length === 0 && (
              <div className="p-4 text-sm text-slate-500">No CVEs match.</div>
            )}
            {data && data.length > 0 && (
              <table className="w-full text-sm">
                <thead className="bg-slate-50 text-xs uppercase text-slate-600">
                  <tr>
                    <th className="text-left px-4 py-2">CVE</th>
                    <th className="text-left px-4 py-2">Severity</th>
                    <th className="text-left px-4 py-2">KEV</th>
                    <th className="text-left px-4 py-2">Published</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200">
                  {data.map((c) => (
                    <tr
                      key={c.cve_id}
                      onClick={() => setSelected(c.cve_id)}
                      className={`cursor-pointer hover:bg-slate-50 ${
                        selected === c.cve_id ? "bg-brand-50" : ""
                      }`}
                    >
                      <td className="px-4 py-2 font-mono text-xs">{c.cve_id}</td>
                      <td className="px-4 py-2">
                        <span className={`badge ${severityColor(c.cvss_v3_severity)}`}>
                          {c.cvss_v3_severity ?? "—"}{" "}
                          {c.cvss_v3 != null && `(${c.cvss_v3})`}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-xs">{c.kev_member ? "yes" : "—"}</td>
                      <td className="px-4 py-2 text-xs text-slate-500">
                        {relTime(c.published_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
        {selected && (
          <CveDetailPane cveId={selected} onClose={() => setSelected(null)} />
        )}
      </div>
    </div>
  );
}

function CveDetailPane({ cveId, onClose }: { cveId: string; onClose: () => void }) {
  const qc = useQueryClient();
  const { data: tags } = useQuery({
    queryKey: ["cve-tags", cveId],
    queryFn: () => getCveTags(cveId),
  });
  const { data: buckets } = useQuery({
    queryKey: ["buckets"],
    queryFn: () => listBuckets(),
  });
  const { data: vendors } = useQuery({
    queryKey: ["vendors"],
    queryFn: () => listVendors(),
  });

  const invalidate = () => qc.invalidateQueries({ queryKey: ["cve-tags", cveId] });

  const addB = useMutation({
    mutationFn: (k: string) => tagBucket(cveId, k),
    onSuccess: invalidate,
  });
  const rmB = useMutation({
    mutationFn: (k: string) => untagBucket(cveId, k),
    onSuccess: invalidate,
  });
  const addV = useMutation({
    mutationFn: (k: string) => tagVendor(cveId, k),
    onSuccess: invalidate,
  });
  const rmV = useMutation({
    mutationFn: (k: string) => untagVendor(cveId, k),
    onSuccess: invalidate,
  });

  const bSet = new Set((tags?.buckets ?? []).map((t) => t.key));
  const vSet = new Set((tags?.vendors ?? []).map((t) => t.key));

  return (
    <div className="card p-4 self-start">
      <div className="flex justify-between items-start mb-3">
        <div className="font-mono text-sm">{cveId}</div>
        <button onClick={onClose} className="text-xs text-slate-500 hover:text-slate-900">
          Close
        </button>
      </div>
      <div className="space-y-3">
        <Section title="Buckets">
          {buckets?.map((b) => {
            const on = bSet.has(b.key);
            return (
              <button
                key={b.id}
                onClick={() => (on ? rmB.mutate(b.key) : addB.mutate(b.key))}
                className={`badge mr-1 mb-1 ${
                  on ? "bg-brand-600 text-white" : "bg-slate-100 text-slate-700"
                }`}
              >
                {b.display_name}
              </button>
            );
          })}
        </Section>
        <Section title="Vendors">
          {vendors?.map((v) => {
            const on = vSet.has(v.key);
            return (
              <button
                key={v.id}
                onClick={() => (on ? rmV.mutate(v.key) : addV.mutate(v.key))}
                className={`badge mr-1 mb-1 ${
                  on ? "bg-brand-600 text-white" : "bg-slate-100 text-slate-700"
                }`}
              >
                {v.display_name}
              </button>
            );
          })}
        </Section>
      </div>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div className="text-xs font-semibold text-slate-600 mb-1">{title}</div>
      <div className="flex flex-wrap">{children}</div>
    </div>
  );
}
