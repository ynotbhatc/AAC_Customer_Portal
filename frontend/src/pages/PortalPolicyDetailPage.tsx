import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  userPolicyDetail,
  userPolicyExtractIr,
  userPolicyGenerateRego,
  userPolicyTargets,
} from "../lib/api";
import { extractErr } from "../lib/utils";
import type {
  CustomerPolicyDetail,
  TargetSummary,
} from "../types/policy";

/**
 * One policy's detail view + the four actions a customer takes against
 * a draft:
 *
 *   1. Extract IR  →  POST /me/policies/{id}/extract-ir
 *   2. Generate Rego  →  POST /me/policies/{id}/generate-rego
 *   3. (View targets — table below; review/approve flows ship in PR 19)
 *   4. (Publish — ships in PR 20 once review is complete)
 *
 * Actions only show when applicable (e.g. Extract IR is hidden if
 * ir_json is already populated; Generate Rego only shows if IR exists).
 */
export default function PortalPolicyDetailPage() {
  const { id = "" } = useParams<{ id: string }>();
  const [policy, setPolicy] = useState<CustomerPolicyDetail | null>(null);
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<"ir" | "rego" | null>(null);

  const loadAll = () => {
    setErr(null);
    Promise.all([userPolicyDetail(id), userPolicyTargets(id)])
      .then(([p, t]) => {
        setPolicy(p);
        setTargets(t);
      })
      .catch((e) => setErr(extractErr(e)));
  };

  useEffect(() => {
    if (id) loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const onExtractIr = async () => {
    setBusy("ir");
    setErr(null);
    try {
      await userPolicyExtractIr(id);
      loadAll();
    } catch (e) {
      setErr(extractErr(e));
    } finally {
      setBusy(null);
    }
  };

  const onGenerateRego = async () => {
    setBusy("rego");
    setErr(null);
    try {
      await userPolicyGenerateRego(id);
      loadAll();
    } catch (e) {
      setErr(extractErr(e));
    } finally {
      setBusy(null);
    }
  };

  if (!policy) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center text-slate-500">
        {err ? <span className="text-red-600">{err}</span> : "Loading…"}
      </div>
    );
  }

  const irControls = (
    (policy.ir_json?.controls as unknown[] | undefined) ?? []
  ).length;

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
          <Link
            to="/portal/policies"
            className="text-sm text-brand-600 hover:underline"
          >
            ← Policies
          </Link>
          <h1 className="text-base font-semibold text-slate-900 truncate">
            {policy.name}
          </h1>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-6">
        {err ? (
          <div className="card p-4 text-sm text-red-600">{err}</div>
        ) : null}

        {/* Policy metadata */}
        <section className="card p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-4">
            Overview
          </h2>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <Field label="Framework">{policy.framework_bucket}</Field>
            <Field label="Source">{policy.policy_source.replace("_", " ")}</Field>
            <Field label="Version">{policy.version_semver}</Field>
            <Field label="Status">
              <code className="text-xs">{policy.status}</code>
            </Field>
            {policy.parent_standard_ref ? (
              <Field label="Parent standard">
                <code className="text-xs">{policy.parent_standard_ref}</code>{" "}
                @ <code className="text-xs">{policy.parent_standard_version}</code>
                <Link
                  to={`/portal/policies/${policy.id}/upstream-diff`}
                  className="ml-3 text-xs text-brand-600 hover:underline"
                >
                  View diff vs upstream
                </Link>
              </Field>
            ) : null}
            <Field label="Source MIME">
              {policy.source_file_mime ?? <span className="text-slate-400">—</span>}
            </Field>
            <Field label="Created">{new Date(policy.created_at).toLocaleString()}</Field>
            <Field label="Updated">{new Date(policy.updated_at).toLocaleString()}</Field>
          </dl>
        </section>

        {/* IR extraction */}
        <section className="card p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900 mb-1">
                Intermediate Representation
              </h2>
              <p className="text-sm text-slate-500">
                Structured JSON of control intents extracted from the policy
                text by the LLM. Required before Rego generation.
              </p>
            </div>
            <div>
              {policy.ir_json ? (
                <span className="text-sm text-emerald-600">
                  ✓ {irControls} controls
                </span>
              ) : null}
            </div>
          </div>
          {policy.policy_source === "prose_upload" ? (
            <div className="mt-4">
              <button
                type="button"
                className="btn-primary text-sm"
                onClick={onExtractIr}
                disabled={busy !== null || policy.status === "published"}
              >
                {busy === "ir"
                  ? "Extracting…"
                  : policy.ir_json
                  ? "Re-extract IR"
                  : "Extract IR"}
              </button>
              {policy.ir_json ? (
                <span className="text-xs text-slate-500 ml-3">
                  Re-running overwrites the prior IR. Audit log preserves
                  the history.
                </span>
              ) : null}
            </div>
          ) : (
            <p className="text-sm text-slate-500 mt-4 italic">
              IR extraction only applies to prose uploads. Forked overlays
              use the parent standard's structure directly.
            </p>
          )}
        </section>

        {/* Rego generation */}
        <section className="card p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-base font-semibold text-slate-900 mb-1">
                Rego generation
              </h2>
              <p className="text-sm text-slate-500">
                Hybrid: templates from the library when available, LLM
                fallback otherwise. Each generated module is validated
                via <code>opa check</code> before storing.
              </p>
            </div>
            <div>
              {targets.length > 0 ? (
                <span className="text-sm text-slate-700">
                  {targets.length} target{targets.length === 1 ? "" : "s"}
                </span>
              ) : null}
            </div>
          </div>
          <div className="mt-4">
            <button
              type="button"
              className="btn-primary text-sm"
              onClick={onGenerateRego}
              disabled={
                busy !== null ||
                policy.status === "published" ||
                (!policy.ir_json && policy.policy_source === "prose_upload")
              }
            >
              {busy === "rego"
                ? "Generating…"
                : targets.length > 0
                ? "Re-generate Rego"
                : "Generate Rego"}
            </button>
            {!policy.ir_json && policy.policy_source === "prose_upload" ? (
              <span className="text-xs text-slate-500 ml-3">
                Extract IR first.
              </span>
            ) : null}
          </div>
        </section>

        {/* Targets table */}
        {targets.length > 0 ? (
          <section className="card overflow-hidden">
            <h2 className="text-base font-semibold text-slate-900 px-6 pt-6 pb-2">
              Targets
            </h2>
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-slate-600">
                <tr>
                  <th className="text-left px-4 py-2 font-medium">Target</th>
                  <th className="text-left px-4 py-2 font-medium">Method</th>
                  <th className="text-left px-4 py-2 font-medium">Confidence</th>
                  <th className="text-left px-4 py-2 font-medium">Review</th>
                  <th className="text-left px-4 py-2 font-medium">Bundle SHA</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => (
                  <tr
                    key={t.id}
                    className="border-t border-slate-100 hover:bg-slate-50"
                  >
                    <td className="px-4 py-2 font-mono text-xs">
                      <Link
                        to={`/portal/policies/${policy.id}/targets/${t.id}`}
                        className="text-brand-600 hover:underline"
                      >
                        {t.target_system}
                        {t.target_subtype ? `/${t.target_subtype}` : ""}
                      </Link>
                    </td>
                    <td className="px-4 py-2 text-slate-700">
                      {t.generation_method.replace("_", " ")}
                    </td>
                    <td className="px-4 py-2 font-mono text-xs">
                      {t.confidence_score === null
                        ? "—"
                        : t.confidence_score.toFixed(2)}
                    </td>
                    <td className="px-4 py-2">
                      <ReviewBadge status={t.review_status} />
                    </td>
                    <td className="px-4 py-2 font-mono text-[10px] text-slate-500">
                      {t.published_in_bundle_sha
                        ? t.published_in_bundle_sha.slice(0, 10)
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="px-6 py-3 text-xs text-slate-500 bg-slate-50 border-t border-slate-100">
              Click a target to review (approve / reject / edit Rego).
            </p>
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

function ReviewBadge({ status }: { status: TargetSummary["review_status"] }) {
  const styles = {
    pending: "bg-amber-100 text-amber-800",
    approved: "bg-emerald-100 text-emerald-800",
    rejected: "bg-red-100 text-red-800",
  } as const;
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${styles[status]}`}
    >
      {status}
    </span>
  );
}
