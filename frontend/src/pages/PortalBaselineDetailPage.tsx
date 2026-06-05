import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { userBaselineDetail } from "../lib/api";
import { extractErr } from "../lib/utils";
import type { BaselineSnapshotDetail } from "../types/baseline";

/**
 * Per-baseline detail view.
 *
 * Renders the same metadata as the list row plus the full
 * by_framework breakdown. Bundle SHA links back to the bundle detail
 * page so the customer can see what was actually loaded when this
 * evaluation ran.
 */
export default function PortalBaselineDetailPage() {
  const { id = "" } = useParams<{ id: string }>();
  const [baseline, setBaseline] = useState<BaselineSnapshotDetail | null>(
    null
  );
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    setErr(null);
    userBaselineDetail(id)
      .then(setBaseline)
      .catch((e) => setErr(extractErr(e)));
  }, [id]);

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
          <Link
            to="/portal/baselines"
            className="text-sm text-brand-600 hover:underline"
          >
            ← Baselines
          </Link>
          <h1 className="text-base font-semibold text-slate-900 truncate">
            {baseline
              ? baseline.label || "Baseline snapshot"
              : "Baseline snapshot"}
          </h1>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-6">
        {err ? (
          <div className="card p-4 text-sm text-red-600">{err}</div>
        ) : null}

        {!baseline ? (
          <section className="card p-6 text-sm text-slate-500">
            {err ? null : "Loading…"}
          </section>
        ) : (
          <>
            <section className="card p-6">
              <h2 className="text-base font-semibold text-slate-900 mb-4">
                Snapshot
              </h2>
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
                <Field label="Captured at">
                  {new Date(baseline.captured_at).toLocaleString()}
                </Field>
                <Field label="Source">
                  <code className="text-xs">{baseline.source}</code>
                </Field>
                <Field label="Captured by">
                  {baseline.captured_by_email ?? (
                    <span className="text-slate-400 italic">
                      bridge (no user)
                    </span>
                  )}
                </Field>
                <Field label="Label">
                  {baseline.label ?? (
                    <span className="text-slate-400">—</span>
                  )}
                </Field>
                <Field label="Bundle">
                  <code className="text-[11px] text-slate-700 break-all">
                    {baseline.bundle_sha256}
                  </code>
                </Field>
                <Field label="Host count">{baseline.summary.host_count}</Field>
                <Field label="Total evaluations">
                  {baseline.summary.total_evaluations}
                </Field>
                <Field label="Errors">
                  {baseline.summary.errors > 0 ? (
                    <span className="text-amber-700">
                      {baseline.summary.errors}
                    </span>
                  ) : (
                    "0"
                  )}
                </Field>
              </dl>
            </section>

            <section className="card p-6">
              <h2 className="text-base font-semibold text-slate-900 mb-3">
                Aggregate
              </h2>
              <div className="flex items-end gap-8">
                <Stat label="Passing" value={baseline.summary.passing} tone="ok" />
                <Stat
                  label="Failing"
                  value={baseline.summary.failing}
                  tone={baseline.summary.failing > 0 ? "bad" : "ok"}
                />
                <Stat label="Errors" value={baseline.summary.errors} tone="warn" />
              </div>
              <PassRate
                passing={baseline.summary.passing}
                total={baseline.summary.total_evaluations}
              />
            </section>

            {Object.keys(baseline.summary.by_framework).length > 0 ? (
              <section className="card overflow-hidden">
                <h2 className="text-base font-semibold text-slate-900 px-6 pt-6 pb-3">
                  Per framework
                </h2>
                <table className="w-full text-sm">
                  <thead className="bg-slate-50 text-slate-600">
                    <tr>
                      <th className="text-left px-4 py-2 font-medium">
                        Framework
                      </th>
                      <th className="text-right px-4 py-2 font-medium w-32">
                        Passing
                      </th>
                      <th className="text-right px-4 py-2 font-medium w-32">
                        Failing
                      </th>
                      <th className="text-right px-4 py-2 font-medium w-32">
                        Pass rate
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(baseline.summary.by_framework)
                      .sort(([a], [b]) => a.localeCompare(b))
                      .map(([fw, s]) => {
                        const total = s.passing + s.failing;
                        const rate =
                          total === 0
                            ? null
                            : ((s.passing / total) * 100).toFixed(1);
                        return (
                          <tr key={fw} className="border-t border-slate-100">
                            <td className="px-4 py-2 font-mono text-xs">
                              {fw}
                            </td>
                            <td className="px-4 py-2 text-right text-emerald-700">
                              {s.passing}
                            </td>
                            <td className="px-4 py-2 text-right">
                              {s.failing > 0 ? (
                                <span className="text-red-700">
                                  {s.failing}
                                </span>
                              ) : (
                                <span className="text-slate-700">0</span>
                              )}
                            </td>
                            <td className="px-4 py-2 text-right text-slate-700">
                              {rate === null ? "—" : `${rate}%`}
                            </td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </section>
            ) : null}
          </>
        )}
      </main>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-slate-900">{children}</dd>
    </div>
  );
}

function Stat({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone: "ok" | "warn" | "bad";
}) {
  const cls =
    tone === "bad"
      ? "text-red-700"
      : tone === "warn"
      ? "text-amber-700"
      : "text-emerald-700";
  return (
    <div>
      <div className="text-xs text-slate-500">{label}</div>
      <div className={`text-3xl font-semibold ${cls}`}>{value}</div>
    </div>
  );
}

function PassRate({ passing, total }: { passing: number; total: number }) {
  if (total === 0) return null;
  const pct = (passing / total) * 100;
  return (
    <div className="mt-4">
      <div className="text-xs text-slate-500 mb-1">
        Pass rate: {pct.toFixed(1)}%
      </div>
      <div className="h-2 rounded bg-slate-200 overflow-hidden">
        <div
          className="h-full bg-emerald-500"
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
