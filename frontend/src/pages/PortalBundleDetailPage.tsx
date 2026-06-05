import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { userBundleManifestById } from "../lib/api";
import { extractErr } from "../lib/utils";
import type { BundleManifest } from "../types/bundle";

/**
 * Full manifest view for a single bundle from the history.
 *
 * Mirrors the current-bundle section on PortalBundlesPage but for an
 * arbitrary bundle by id (not just the most recent). Bundle bytes and
 * the signed envelope are never fetched here — the bridge pulls those
 * directly via its M2M token; loading them into the UI would burn
 * memory for nothing.
 */
export default function PortalBundleDetailPage() {
  const { bundleId = "" } = useParams<{ bundleId: string }>();
  const [manifest, setManifest] = useState<BundleManifest | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [manifestExpanded, setManifestExpanded] = useState(false);

  useEffect(() => {
    if (!bundleId) return;
    setErr(null);
    userBundleManifestById(bundleId)
      .then(setManifest)
      .catch((e) => setErr(extractErr(e)));
  }, [bundleId]);

  if (err) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center text-sm text-red-600">
        {err}
      </div>
    );
  }
  if (!manifest) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center text-sm text-slate-500">
        Loading…
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
          <Link
            to="/portal/bundles"
            className="text-sm text-brand-600 hover:underline"
          >
            ← Bundles
          </Link>
          <h1 className="text-base font-semibold text-slate-900 truncate">
            Bundle{" "}
            <code className="text-xs font-mono">
              {manifest.bundle_sha256.slice(0, 12)}…
            </code>
          </h1>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-6">
        <section className="card p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-4">
            Manifest
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
            <Field label="Targets in bundle">{manifest.target_count}</Field>
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
              failed on the saved Rego at build time.
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
                    <td className="px-4 py-2 text-slate-700">{e.reason}</td>
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
