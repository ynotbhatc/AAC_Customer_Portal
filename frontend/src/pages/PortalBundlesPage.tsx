import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  userBundleBuild,
  userBundleCurrentManifest,
  userBundleHistory,
} from "../lib/api";
import { extractErr } from "../lib/utils";
import type { BundleHistoryEntry, BundleManifest } from "../types/bundle";

const HISTORY_PAGE_SIZE = 50;

/**
 * The customer's view of their signed policy bundle.
 *
 *   - "Current bundle" reads /me/bundles/current/manifest. A 404 is
 *     the empty state (no bundle built yet), not an error.
 *   - "Build new bundle" calls /me/bundles/build. The build is
 *     idempotent in effect: same approved set → same bytes.
 *   - The signed envelope is what the AAC bridge verifies on pull —
 *     this page surfaces the signing_key_id so the customer can match
 *     it against what the bridge has cached.
 *
 * Bundle bytes are NEVER fetched into the UI. The bridge pulls them
 * directly via its M2M token. Showing them here would burn megabytes
 * of memory for nothing.
 */
export default function PortalBundlesPage() {
  const [manifest, setManifest] = useState<BundleManifest | null>(null);
  const [empty, setEmpty] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [manifestExpanded, setManifestExpanded] = useState(false);

  const [history, setHistory] = useState<BundleHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyHasMore, setHistoryHasMore] = useState(true);

  const load = () => {
    setErr(null);
    userBundleCurrentManifest()
      .then((m) => {
        setManifest(m);
        setEmpty(false);
      })
      .catch((e) => {
        const status = (e as { response?: { status?: number } }).response
          ?.status;
        if (status === 404) {
          setManifest(null);
          setEmpty(true);
        } else {
          setErr(extractErr(e));
        }
      });

    setHistoryLoading(true);
    userBundleHistory({ limit: HISTORY_PAGE_SIZE })
      .then((rows) => {
        setHistory(rows);
        setHistoryHasMore(rows.length === HISTORY_PAGE_SIZE);
      })
      .catch((e) => setErr(extractErr(e)))
      .finally(() => setHistoryLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const loadOlderHistory = () => {
    if (history.length === 0) return;
    const oldest = history[history.length - 1].built_at;
    setHistoryLoading(true);
    setErr(null);
    userBundleHistory({
      limit: HISTORY_PAGE_SIZE,
      before_built_at: oldest,
    })
      .then((rows) => {
        setHistory((prev) => [...prev, ...rows]);
        setHistoryHasMore(rows.length === HISTORY_PAGE_SIZE);
      })
      .catch((e) => setErr(extractErr(e)))
      .finally(() => setHistoryLoading(false));
  };

  const onBuild = async () => {
    setBusy(true);
    setErr(null);
    try {
      await userBundleBuild();
      load();
    } catch (e) {
      setErr(extractErr(e));
    } finally {
      setBusy(false);
    }
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
            Policy bundles
          </h1>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-6">
        {err ? (
          <div className="card p-4 text-sm text-red-600">{err}</div>
        ) : null}

        <section className="card p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-1">
            Build a new bundle
          </h2>
          <p className="text-sm text-slate-500 mb-4">
            Folds all approved targets from published policies into a single
            signed bundle. The build is idempotent — the same approved set
            produces the same bytes.
          </p>
          <button
            type="button"
            className="btn-primary text-sm"
            onClick={onBuild}
            disabled={busy}
          >
            {busy ? "Building…" : "Build bundle"}
          </button>
        </section>

        {empty ? (
          <section className="card p-6 text-sm text-slate-500">
            No bundle has been built for this tenant yet. Publish at least
            one policy with an approved target, then click <strong>Build
            bundle</strong> above.
          </section>
        ) : manifest ? (
          <>
            <section className="card p-6">
              <h2 className="text-base font-semibold text-slate-900 mb-4">
                Current bundle
              </h2>
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
                <Field label="Bundle SHA-256">
                  <code className="text-[11px] text-slate-700 break-all">
                    {manifest.bundle_sha256}
                  </code>
                </Field>
                <Field label="Bundle size">
                  {humanBytes(manifest.bundle_byte_size)}
                </Field>
                <Field label="Built at">
                  {new Date(manifest.built_at).toLocaleString()}
                </Field>
                <Field label="Signing key ID">
                  <code className="text-xs">{manifest.signing_key_id}</code>
                </Field>
                <Field label="Targets in bundle">
                  {manifest.target_count}
                </Field>
                <Field label="Targets excluded">
                  {manifest.excluded_target_count > 0 ? (
                    <span className="text-amber-700">
                      {manifest.excluded_target_count}
                    </span>
                  ) : (
                    "0"
                  )}
                </Field>
                <Field label="Source policies">
                  <span className="font-mono text-xs">
                    {manifest.customer_policy_ids.length} policies
                  </span>
                </Field>
              </dl>
            </section>

            {manifest.excluded_target_count > 0 ? (
              <section className="card overflow-hidden">
                <h2 className="text-base font-semibold text-slate-900 px-6 pt-6 pb-2">
                  Excluded targets
                </h2>
                <p className="px-6 pb-4 text-xs text-slate-500">
                  Approved targets that the builder dropped — usually because
                  <code className="mx-1">opa check</code>
                  failed on the saved Rego at build time. Re-open the target
                  and re-edit to fix.
                </p>
                <table className="w-full text-sm">
                  <thead className="bg-slate-50 text-slate-600">
                    <tr>
                      <th className="text-left px-4 py-2 font-medium">Target</th>
                      <th className="text-left px-4 py-2 font-medium">Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {manifest.excluded_targets_log.map((e, idx) => (
                      <tr key={idx} className="border-t border-slate-100">
                        <td className="px-4 py-2 font-mono text-xs">
                          {e.target_system}
                          {e.target_subtype ? `/${e.target_subtype}` : ""}
                        </td>
                        <td className="px-4 py-2 text-slate-700">
                          {e.reason}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            ) : null}

            <section className="card overflow-hidden">
              <button
                type="button"
                onClick={() => setManifestExpanded((x) => !x)}
                className="w-full px-6 py-4 flex items-center justify-between hover:bg-slate-50"
              >
                <span className="text-base font-semibold text-slate-900">
                  Builder manifest
                </span>
                <span className="text-xs text-slate-500">
                  {manifestExpanded ? "Hide" : "Show"}
                </span>
              </button>
              {manifestExpanded ? (
                <pre className="text-[11px] font-mono leading-snug p-6 overflow-x-auto bg-white whitespace-pre-wrap border-t border-slate-100">
                  {JSON.stringify(manifest.manifest, null, 2)}
                </pre>
              ) : null}
            </section>
          </>
        ) : (
          <section className="card p-6 text-sm text-slate-500">
            Loading…
          </section>
        )}

        {/* Bundle history — shown whenever there's at least one row.
            When `empty` is true (no bundles ever built) the history
            table is naturally empty too, so we don't bother rendering
            an "empty history" message — the build prompt above
            already covers that state. */}
        {history.length > 0 ? (
          <section className="card overflow-hidden">
            <h2 className="text-base font-semibold text-slate-900 px-6 pt-6 pb-2">
              History
            </h2>
            <p className="px-6 pb-4 text-xs text-slate-500">
              Every build leaves a row. The most recent is the
              "current" bundle the bridge will pull on its next poll.
            </p>
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-slate-600">
                <tr>
                  <th className="text-left px-4 py-2 font-medium w-44">
                    Built at
                  </th>
                  <th className="text-left px-4 py-2 font-medium">SHA-256</th>
                  <th className="text-left px-4 py-2 font-medium">Size</th>
                  <th className="text-left px-4 py-2 font-medium">Targets</th>
                  <th className="text-left px-4 py-2 font-medium">Excluded</th>
                  <th className="text-left px-4 py-2 font-medium">Built by</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h, idx) => {
                  const isCurrent =
                    manifest?.bundle_sha256 === h.bundle_sha256 && idx === 0;
                  return (
                    <tr
                      key={h.bundle_id}
                      className="border-t border-slate-100 align-top"
                    >
                      <td className="px-4 py-2 text-slate-700 whitespace-nowrap">
                        {new Date(h.built_at).toLocaleString()}
                        {isCurrent ? (
                          <span className="ml-2 inline-block bg-emerald-100 text-emerald-800 text-[10px] font-medium px-1.5 py-0.5 rounded">
                            current
                          </span>
                        ) : null}
                      </td>
                      <td className="px-4 py-2">
                        <code className="text-[11px] text-slate-700">
                          {h.bundle_sha256.slice(0, 12)}…
                        </code>
                      </td>
                      <td className="px-4 py-2 text-slate-700">
                        {humanBytes(h.bundle_byte_size)}
                      </td>
                      <td className="px-4 py-2 text-slate-700">
                        {h.target_count}
                      </td>
                      <td className="px-4 py-2 text-slate-700">
                        {h.excluded_target_count > 0 ? (
                          <span className="text-amber-700">
                            {h.excluded_target_count}
                          </span>
                        ) : (
                          "0"
                        )}
                      </td>
                      <td className="px-4 py-2 text-slate-700">
                        {h.built_by_email ?? (
                          <span className="text-slate-400 italic">
                            (user removed)
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <div className="px-6 py-3 bg-slate-50 border-t border-slate-100 flex items-center justify-center">
              {historyHasMore ? (
                <button
                  type="button"
                  className="btn-secondary text-sm"
                  onClick={loadOlderHistory}
                  disabled={historyLoading}
                >
                  {historyLoading ? "Loading…" : "Load older"}
                </button>
              ) : (
                <span className="text-xs text-slate-400">
                  End of history.
                </span>
              )}
            </div>
          </section>
        ) : null}
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

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
