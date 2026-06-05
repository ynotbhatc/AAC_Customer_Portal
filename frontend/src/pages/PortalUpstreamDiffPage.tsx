import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { userPolicyUpstreamDiff } from "../lib/api";
import { extractErr } from "../lib/utils";
import type { UpstreamDiff } from "../types/library";

/**
 * Unified diff between a forked overlay and current upstream.
 *
 * Renders the server's unified-diff string with line-level coloring
 * (additions green, deletions red, hunk headers slate). Designed to
 * read at a glance — anything fancier (side-by-side, syntax
 * highlighting) waits on a real diff library decision.
 *
 * Surfaces upstream_changed_since_fork prominently — that's the
 * drift-detection signal the customer cares about.
 */
export default function PortalUpstreamDiffPage() {
  const { id = "" } = useParams<{ id: string }>();
  const [diff, setDiff] = useState<UpstreamDiff | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    userPolicyUpstreamDiff(id)
      .then(setDiff)
      .catch((e) => setErr(extractErr(e)));
  }, [id]);

  if (err) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center text-red-600 text-sm">
        {err}
      </div>
    );
  }
  if (!diff) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center text-slate-500 text-sm">
        Loading…
      </div>
    );
  }

  const lines = diff.unified_diff.split("\n");
  const noChanges = diff.unified_diff.trim() === "";

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
          <Link
            to={`/portal/policies/${id}`}
            className="text-sm text-brand-600 hover:underline"
          >
            ← Policy
          </Link>
          <h1 className="text-base font-semibold text-slate-900">
            Upstream diff
          </h1>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-4">
        <section className="card p-6">
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <div>
              <dt className="text-slate-500">Parent standard</dt>
              <dd className="font-mono text-xs text-slate-900 break-all">
                {diff.parent_standard_ref}
              </dd>
            </div>
            <div>
              <dt className="text-slate-500">Pinned version</dt>
              <dd className="font-mono text-xs text-slate-900">
                {diff.parent_standard_version}
              </dd>
            </div>
            <div>
              <dt className="text-slate-500">Fork sha (when forked)</dt>
              <dd className="font-mono text-[11px] text-slate-700">
                {diff.fork_sha256.slice(0, 16)}…
              </dd>
            </div>
            <div>
              <dt className="text-slate-500">Overlay sha (now)</dt>
              <dd className="font-mono text-[11px] text-slate-700">
                {diff.overlay_sha256.slice(0, 16)}…
              </dd>
            </div>
            <div>
              <dt className="text-slate-500">Upstream sha (now)</dt>
              <dd className="font-mono text-[11px] text-slate-700">
                {diff.current_upstream_sha256.slice(0, 16)}…
              </dd>
            </div>
            <div>
              <dt className="text-slate-500">Upstream moved since fork</dt>
              <dd>
                {diff.upstream_changed_since_fork ? (
                  <span className="text-amber-700 font-medium">
                    Yes — review changes before next bundle
                  </span>
                ) : (
                  <span className="text-emerald-600">No</span>
                )}
              </dd>
            </div>
          </dl>
        </section>

        <section className="card overflow-hidden">
          <div className="px-4 py-2 bg-slate-50 text-xs text-slate-500 border-b border-slate-200">
            Unified diff
          </div>
          {noChanges ? (
            <div className="px-4 py-6 text-sm text-slate-500 text-center">
              No differences — your overlay still matches upstream.
            </div>
          ) : (
            <pre className="text-[11px] font-mono p-0 overflow-x-auto leading-snug bg-white">
              {lines.map((line, i) => {
                let cls = "px-4";
                if (line.startsWith("+++") || line.startsWith("---")) {
                  cls += " bg-slate-100 text-slate-600";
                } else if (line.startsWith("@@")) {
                  cls += " bg-slate-50 text-brand-700";
                } else if (line.startsWith("+")) {
                  cls += " bg-emerald-50 text-emerald-900";
                } else if (line.startsWith("-")) {
                  cls += " bg-red-50 text-red-900";
                } else {
                  cls += " text-slate-700";
                }
                return (
                  <div key={i} className={cls}>
                    {line || " "}
                  </div>
                );
              })}
            </pre>
          )}
        </section>
      </main>
    </div>
  );
}
