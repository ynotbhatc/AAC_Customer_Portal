import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  portalAckCve,
  portalListCves,
  portalSuppressCve,
  portalWhoAmI,
} from "../lib/api";
import { clearTenantCreds, getTenantCreds } from "../lib/auth";
import type { PortalCveItem, PortalCveResponse, Severity } from "../types/cve";
import { extractErr, relTime, severityColor } from "../lib/utils";

export default function MyProductsPage() {
  const navigate = useNavigate();
  const creds = getTenantCreds();

  useEffect(() => {
    if (!creds) navigate("/my-products/login", { replace: true });
  }, [creds, navigate]);

  if (!creds) return null;

  return <MyProductsView tenantId={creds.tenantId} />;
}

function MyProductsView({ tenantId }: { tenantId: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [sev, setSev] = useState<Severity | "">("");
  const [kev, setKev] = useState(false);
  const [includeAck, setIncludeAck] = useState(false);
  const [includeSup, setIncludeSup] = useState(false);

  const { data: who } = useQuery({
    queryKey: ["whoami", tenantId],
    queryFn: () => portalWhoAmI(tenantId),
  });

  const { data: feed, isLoading, error } = useQuery({
    queryKey: ["my-cves", tenantId, sev, kev, includeAck, includeSup],
    queryFn: () =>
      portalListCves(tenantId, {
        severity: sev || undefined,
        kev_only: kev || undefined,
        include_acknowledged: includeAck || undefined,
        include_suppressed: includeSup || undefined,
        limit: 200,
      }),
  });

  const ack = useMutation({
    mutationFn: (cve: string) => portalAckCve(tenantId, cve),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["my-cves", tenantId] }),
  });
  const suppress = useMutation({
    mutationFn: ({ cve, reason }: { cve: string; reason: string }) =>
      portalSuppressCve(tenantId, cve, reason),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["my-cves", tenantId] }),
  });

  const onLogout = () => {
    clearTenantCreds();
    navigate("/my-products/login", { replace: true });
  };

  // Backend may return either an array (legacy) or { items: [...] } (paged).
  const items: PortalCveItem[] = Array.isArray(feed)
    ? feed
    : ((feed as PortalCveResponse | undefined)?.items ?? []);

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div>
            <div className="text-xs text-slate-500">My Products — CVE feed</div>
            <div className="text-lg font-semibold">
              {who?.tenant_display_name ?? "…"}
            </div>
          </div>
          <div className="text-right">
            <div className="text-xs text-slate-500">{who?.token_id ?? ""}</div>
            <button
              onClick={onLogout}
              className="text-xs text-slate-500 hover:text-slate-900 underline"
            >
              Disconnect
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-6xl mx-auto px-6 py-6 space-y-4">
        <div className="card p-4 flex flex-wrap gap-3 items-end">
          <div>
            <label className="label">Minimum severity</label>
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
          <label className="flex items-center gap-2 text-sm text-slate-700 mb-2">
            <input
              type="checkbox"
              checked={includeAck}
              onChange={(e) => setIncludeAck(e.target.checked)}
            />
            Include acknowledged
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-700 mb-2">
            <input
              type="checkbox"
              checked={includeSup}
              onChange={(e) => setIncludeSup(e.target.checked)}
            />
            Include suppressed
          </label>
        </div>

        {error && (
          <div className="card p-4 text-red-700 text-sm">{extractErr(error)}</div>
        )}
        {isLoading && <div className="text-slate-500 text-sm">Loading…</div>}

        {items.length === 0 && !isLoading && !error && (
          <div className="card p-8 text-center text-slate-500">
            No matching CVEs at this filter. 🎉
          </div>
        )}

        <div className="space-y-2">
          {items.map((c) => (
            <CveCard
              key={c.cve_id}
              cve={c}
              onAck={() => ack.mutate(c.cve_id)}
              onSuppress={(reason) =>
                suppress.mutate({ cve: c.cve_id, reason })
              }
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function CveCard({
  cve,
  onAck,
  onSuppress,
}: {
  cve: PortalCveItem;
  onAck: () => void;
  onSuppress: (reason: string) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="card p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm">{cve.cve_id}</span>
            <span className={`badge ${severityColor(cve.cvss_v3_severity)}`}>
              {cve.cvss_v3_severity ?? "—"}{" "}
              {cve.cvss_v3 != null && `(${cve.cvss_v3})`}
            </span>
            {cve.kev_member && (
              <span className="badge bg-red-100 text-red-800">KEV</span>
            )}
            {cve.acknowledged_at && (
              <span className="badge bg-slate-200 text-slate-700">
                acked {relTime(cve.acknowledged_at)}
              </span>
            )}
            {cve.suppressed_at && (
              <span className="badge bg-slate-300 text-slate-700">
                suppressed
              </span>
            )}
          </div>
          {cve.description && (
            <p className="text-sm text-slate-700 mt-2 line-clamp-2">
              {cve.description}
            </p>
          )}
          <div className="text-xs text-slate-500 mt-2">
            Matched {relTime(cve.matched_at)}
          </div>
        </div>
        <div className="flex flex-col gap-2 shrink-0">
          {!cve.acknowledged_at && (
            <button className="btn-secondary text-xs" onClick={onAck}>
              Acknowledge
            </button>
          )}
          {!cve.suppressed_at && (
            <button
              className="btn-danger text-xs"
              onClick={() => {
                const reason = prompt("Suppression reason?", "");
                if (reason !== null) onSuppress(reason);
              }}
            >
              Suppress
            </button>
          )}
          <button
            className="text-xs text-slate-500 hover:text-slate-900"
            onClick={() => setOpen(!open)}
          >
            {open ? "Hide details" : "Show details"}
          </button>
        </div>
      </div>

      {open && (
        <div className="mt-4 pt-4 border-t border-slate-200 space-y-3">
          {cve.description && (
            <div>
              <div className="text-xs font-semibold text-slate-600">Description</div>
              <p className="text-sm text-slate-700 whitespace-pre-wrap">
                {cve.description}
              </p>
            </div>
          )}
          {cve.references && cve.references.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-600">References</div>
              <ul className="text-sm list-disc list-inside">
                {cve.references.map((r, i) => (
                  <li key={i}>
                    <a
                      href={r.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-brand-600 hover:underline"
                    >
                      {r.url}
                    </a>{" "}
                    <span className="text-xs text-slate-500">({r.source})</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {cve.remediations && cve.remediations.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-600">
                Vendor remediations
              </div>
              <ul className="text-sm list-disc list-inside">
                {cve.remediations.map((r, i) => (
                  <li key={i}>
                    <span className="font-medium">{r.vendor}</span>{" "}
                    {r.fixed_version && (
                      <span className="text-slate-600">→ {r.fixed_version}</span>
                    )}{" "}
                    {r.advisory_url && (
                      <a
                        href={r.advisory_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-brand-600 hover:underline"
                      >
                        advisory
                      </a>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
