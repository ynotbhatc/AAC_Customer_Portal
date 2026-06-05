import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { userBaselinesList } from "../lib/api";
import { extractErr } from "../lib/utils";
import type {
  BaselineSnapshotSummary,
  BaselineSource,
} from "../types/baseline";

/**
 * Baseline history list.
 *
 * Each row is one snapshot the bridge POSTed (or an operator manually
 * imported). Click a row to drill into its full summary breakdown.
 *
 * Cursor-paginated on the compound (captured_at, id) key — pair both
 * cursor params from the oldest entry of the prior page. Server 400s
 * on a mismatched pair.
 *
 * Empty state is its own card — no special "no bundle yet" routing is
 * needed because list returning [] is the normal pre-first-snapshot
 * state, not an error.
 */
const PAGE_SIZE = 50;

export default function PortalBaselinesPage() {
  const [rows, setRows] = useState<BaselineSnapshotSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [hasMore, setHasMore] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setErr(null);
    userBaselinesList({ limit: PAGE_SIZE })
      .then((r) => {
        setRows(r);
        setHasMore(r.length === PAGE_SIZE);
      })
      .catch((e) => setErr(extractErr(e)))
      .finally(() => setLoading(false));
  }, []);

  const loadOlder = () => {
    if (rows.length === 0) return;
    const oldest = rows[rows.length - 1];
    setLoading(true);
    setErr(null);
    userBaselinesList({
      limit: PAGE_SIZE,
      before_captured_at: oldest.captured_at,
      before_id: oldest.id,
    })
      .then((older) => {
        setRows((prev) => [...prev, ...older]);
        setHasMore(older.length === PAGE_SIZE);
      })
      .catch((e) => setErr(extractErr(e)))
      .finally(() => setLoading(false));
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
            Compliance baselines
          </h1>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-4">
        {err ? (
          <div className="card p-4 text-sm text-red-600">{err}</div>
        ) : null}

        <section className="card p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-1">
            About baselines
          </h2>
          <p className="text-sm text-slate-500">
            A baseline snapshot is your environment's compliance state
            at a point in time — what bundle the bridge had loaded into
            OPA, and how many evaluations passed and failed across the
            estate. Use the timeline below to see drift over time.
          </p>
        </section>

        {!loading && rows.length === 0 ? (
          <section className="card p-6 text-sm text-slate-500">
            No baselines captured yet. Once your bridge runs an
            evaluation against a published bundle, the result lands
            here automatically.
          </section>
        ) : null}

        {rows.length > 0 ? (
          <section className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-slate-600">
                <tr>
                  <th className="text-left px-4 py-2 font-medium w-44">
                    Captured at
                  </th>
                  <th className="text-left px-4 py-2 font-medium">Label</th>
                  <th className="text-left px-4 py-2 font-medium">Bundle</th>
                  <th className="text-left px-4 py-2 font-medium w-20">
                    Hosts
                  </th>
                  <th className="text-left px-4 py-2 font-medium w-24">
                    Passing
                  </th>
                  <th className="text-left px-4 py-2 font-medium w-24">
                    Failing
                  </th>
                  <th className="text-left px-4 py-2 font-medium w-28">
                    Source
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((b) => (
                  <tr
                    key={b.id}
                    className="border-t border-slate-100 hover:bg-slate-50"
                  >
                    <td className="px-4 py-2 text-slate-700 whitespace-nowrap">
                      <Link
                        to={`/portal/baselines/${b.id}`}
                        className="text-brand-600 hover:underline"
                      >
                        {new Date(b.captured_at).toLocaleString()}
                      </Link>
                    </td>
                    <td className="px-4 py-2 text-slate-700">
                      {b.label ?? (
                        <span className="text-slate-400">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <code className="text-[11px] text-slate-700">
                        {b.bundle_sha256.slice(0, 12)}…
                      </code>
                    </td>
                    <td className="px-4 py-2 text-slate-700">
                      {b.host_count}
                    </td>
                    <td className="px-4 py-2 text-emerald-700">
                      {b.passing}
                    </td>
                    <td className="px-4 py-2">
                      {b.failing > 0 ? (
                        <span className="text-red-700">{b.failing}</span>
                      ) : (
                        <span className="text-slate-700">0</span>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <SourceBadge source={b.source} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="px-6 py-3 bg-slate-50 border-t border-slate-100 flex items-center justify-center">
              {hasMore ? (
                <button
                  type="button"
                  className="btn-secondary text-sm"
                  onClick={loadOlder}
                  disabled={loading}
                >
                  {loading ? "Loading…" : "Load older"}
                </button>
              ) : (
                <span className="text-xs text-slate-400">End of history.</span>
              )}
            </div>
          </section>
        ) : null}
      </main>
    </div>
  );
}

function SourceBadge({ source }: { source: BaselineSource }) {
  // Color by how the snapshot landed — bridge (sky), manual (amber),
  // scheduled (slate). Unknown values fall through to slate so new
  // values can land without breaking the UI.
  const cls =
    source === "bridge_push"
      ? "bg-sky-100 text-sky-800"
      : source === "manual"
      ? "bg-amber-100 text-amber-800"
      : "bg-slate-100 text-slate-700";
  return (
    <span
      className={`inline-block text-xs font-mono px-2 py-0.5 rounded ${cls}`}
    >
      {source}
    </span>
  );
}
