import { Fragment, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { userPolicyAuditLog, userPolicyDetail } from "../lib/api";
import { extractErr } from "../lib/utils";
import type { AuditLogEntry } from "../types/audit";
import type { CustomerPolicyDetail } from "../types/policy";

/**
 * Reverse-chronological audit log for one policy.
 *
 * Backed by GET /me/policies/{id}/audit-log, which is cursor-paginated
 * on the bigserial `id`. The page walks back through history by passing
 * the smallest id from the previous response as `before_id`.
 *
 * Each row shows action, actor (email or "(user removed)"), wall time,
 * and a click-to-expand JSON details view. Details vary by action —
 * the server-side INSERTs emit jsonb shapes tied to each action — so
 * we render them as raw JSON rather than try to format per action.
 */
const PAGE_SIZE = 50;

export default function PortalPolicyAuditLogPage() {
  const { id = "" } = useParams<{ id: string }>();
  const [policy, setPolicy] = useState<CustomerPolicyDetail | null>(null);
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const loadFirstPage = () => {
    setErr(null);
    setLoading(true);
    Promise.all([
      userPolicyDetail(id),
      userPolicyAuditLog(id, { limit: PAGE_SIZE }),
    ])
      .then(([p, rows]) => {
        setPolicy(p);
        setEntries(rows);
        setHasMore(rows.length === PAGE_SIZE);
      })
      .catch((e) => setErr(extractErr(e)))
      .finally(() => setLoading(false));
  };

  const loadMore = () => {
    if (entries.length === 0) return;
    const oldest = entries[entries.length - 1].id;
    setLoading(true);
    setErr(null);
    userPolicyAuditLog(id, { limit: PAGE_SIZE, before_id: oldest })
      .then((rows) => {
        setEntries((prev) => [...prev, ...rows]);
        setHasMore(rows.length === PAGE_SIZE);
      })
      .catch((e) => setErr(extractErr(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (id) loadFirstPage();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const toggleExpanded = (entryId: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(entryId)) next.delete(entryId);
      else next.add(entryId);
      return next;
    });
  };

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
          <h1 className="text-base font-semibold text-slate-900 truncate">
            {policy ? `${policy.name} — audit log` : "Audit log"}
          </h1>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-4">
        {err ? (
          <div className="card p-4 text-sm text-red-600">{err}</div>
        ) : null}

        {!policy && loading ? (
          <div className="card p-6 text-sm text-slate-500">Loading…</div>
        ) : entries.length === 0 ? (
          <div className="card p-6 text-sm text-slate-500">
            No audit entries yet. Actions (upload, IR extraction, Rego
            generation, target review, publish) appear here as they happen.
          </div>
        ) : (
          <>
            <section className="card overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-slate-50 text-slate-600">
                  <tr>
                    <th className="text-left px-4 py-2 font-medium w-44">
                      When
                    </th>
                    <th className="text-left px-4 py-2 font-medium">Action</th>
                    <th className="text-left px-4 py-2 font-medium">Actor</th>
                    <th className="text-right px-4 py-2 font-medium w-20">
                      Details
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => {
                    const open = expanded.has(e.id);
                    const hasDetails = Object.keys(e.details).length > 0;
                    return (
                      <Fragment key={e.id}>
                        <tr className="border-t border-slate-100 align-top">
                          <td className="px-4 py-2 text-slate-700 whitespace-nowrap">
                            {new Date(e.at).toLocaleString()}
                          </td>
                          <td className="px-4 py-2">
                            <ActionBadge action={e.action} />
                          </td>
                          <td className="px-4 py-2 text-slate-700">
                            {e.actor_email ?? (
                              <span className="text-slate-400 italic">
                                (user removed)
                              </span>
                            )}
                          </td>
                          <td className="px-4 py-2 text-right">
                            {hasDetails ? (
                              <button
                                type="button"
                                onClick={() => toggleExpanded(e.id)}
                                className="text-xs text-brand-600 hover:underline"
                              >
                                {open ? "Hide" : "Show"}
                              </button>
                            ) : (
                              <span className="text-xs text-slate-400">—</span>
                            )}
                          </td>
                        </tr>
                        {open ? (
                          <tr className="bg-slate-50 border-t border-slate-100">
                            <td colSpan={4} className="px-4 py-3">
                              <pre className="text-[11px] font-mono leading-snug whitespace-pre-wrap overflow-x-auto">
                                {JSON.stringify(e.details, null, 2)}
                              </pre>
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </section>

            <div className="flex items-center justify-center">
              {hasMore ? (
                <button
                  type="button"
                  className="btn-secondary text-sm"
                  onClick={loadMore}
                  disabled={loading}
                >
                  {loading ? "Loading…" : "Load older"}
                </button>
              ) : (
                <span className="text-xs text-slate-400">
                  End of history.
                </span>
              )}
            </div>
          </>
        )}
      </main>
    </div>
  );
}

// Color-codes by action family so a compliance reviewer can scan
// the log visually. Falls back to a neutral slate for unknown
// actions — new INSERT shapes can land without breaking the UI.
function ActionBadge({ action }: { action: string }) {
  const cls = badgeClass(action);
  return (
    <code
      className={`inline-block text-xs font-mono px-2 py-0.5 rounded ${cls}`}
    >
      {action}
    </code>
  );
}

function badgeClass(action: string): string {
  if (action === "published" || action === "target_approved") {
    return "bg-emerald-100 text-emerald-800";
  }
  if (action === "target_rejected") {
    return "bg-red-100 text-red-800";
  }
  if (action === "target_edited") {
    return "bg-amber-100 text-amber-800";
  }
  if (action.startsWith("bundle_")) {
    return "bg-blue-100 text-blue-800";
  }
  return "bg-slate-100 text-slate-700";
}
