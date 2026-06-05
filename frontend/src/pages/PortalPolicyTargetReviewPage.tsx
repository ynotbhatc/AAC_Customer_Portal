import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  userPolicyDetail,
  userPolicyTargetApprove,
  userPolicyTargetDetail,
  userPolicyTargetEdit,
  userPolicyTargetReject,
} from "../lib/api";
import { extractErr } from "../lib/utils";
import type {
  CustomerPolicyDetail,
  TargetDetail,
} from "../types/policy";

/**
 * Per-target review screen for a draft policy.
 *
 *   - Read-only Rego viewer with an "Edit" affordance.
 *   - Edit submits PATCH; a 422 from `opa check` surfaces stderr inline
 *     so the customer can see exactly what to fix without leaving the page.
 *   - Approve / Reject mutate review_status. Reject requires a reason
 *     (the server accepts a null reason but the workflow says we should
 *     always capture WHY a target was rejected).
 *   - All mutations are blocked when the parent policy is published —
 *     server returns 409, but we hide the actions client-side so the user
 *     never sees a hostile error for a state we already know about.
 */
export default function PortalPolicyTargetReviewPage() {
  const { policyId = "", targetId = "" } = useParams<{
    policyId: string;
    targetId: string;
  }>();

  const [policy, setPolicy] = useState<CustomerPolicyDetail | null>(null);
  const [target, setTarget] = useState<TargetDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const [editing, setEditing] = useState(false);
  const [draftRego, setDraftRego] = useState("");
  const [opaStderr, setOpaStderr] = useState<string | null>(null);

  const [rejectReason, setRejectReason] = useState("");
  const [approveReason, setApproveReason] = useState("");
  const [busy, setBusy] = useState<"edit" | "approve" | "reject" | null>(null);

  const loadAll = () => {
    setErr(null);
    Promise.all([
      userPolicyDetail(policyId),
      userPolicyTargetDetail(policyId, targetId),
    ])
      .then(([p, t]) => {
        setPolicy(p);
        setTarget(t);
        setDraftRego(t.rego_text);
      })
      .catch((e) => setErr(extractErr(e)));
  };

  useEffect(() => {
    if (policyId && targetId) loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policyId, targetId]);

  const frozen = policy?.status === "published";

  const onSaveEdit = async () => {
    setBusy("edit");
    setErr(null);
    setOpaStderr(null);
    try {
      const updated = await userPolicyTargetEdit(policyId, targetId, {
        rego_text: draftRego,
      });
      setTarget(updated);
      setDraftRego(updated.rego_text);
      setEditing(false);
    } catch (e) {
      // The PATCH returns 422 with `{reason, stderr}` when `opa check`
      // fails. Surface stderr inline so the customer sees the parse error
      // next to their edit — much better UX than a generic toast.
      const stderr = extractOpaStderr(e);
      if (stderr) setOpaStderr(stderr);
      else setErr(extractErr(e));
    } finally {
      setBusy(null);
    }
  };

  const onCancelEdit = () => {
    if (target) setDraftRego(target.rego_text);
    setOpaStderr(null);
    setEditing(false);
  };

  const onApprove = async () => {
    setBusy("approve");
    setErr(null);
    try {
      await userPolicyTargetApprove(policyId, targetId, {
        reason: approveReason.trim() || null,
      });
      // Re-fetch the full TargetDetail rather than spreading a
      // TargetSummary into local state — if the server ever mutates
      // additional fields on approve (e.g. last_reviewed_at), this
      // keeps the UI accurate without re-coding when the model
      // evolves.
      const fresh = await userPolicyTargetDetail(policyId, targetId);
      setTarget(fresh);
      setApproveReason("");
    } catch (e) {
      setErr(extractErr(e));
    } finally {
      setBusy(null);
    }
  };

  const onReject = async () => {
    if (!rejectReason.trim()) return;
    setBusy("reject");
    setErr(null);
    try {
      await userPolicyTargetReject(policyId, targetId, {
        reason: rejectReason.trim(),
      });
      const fresh = await userPolicyTargetDetail(policyId, targetId);
      setTarget(fresh);
      setRejectReason("");
    } catch (e) {
      setErr(extractErr(e));
    } finally {
      setBusy(null);
    }
  };

  if (!target || !policy) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center text-slate-500">
        {err ? <span className="text-red-600">{err}</span> : "Loading…"}
      </div>
    );
  }

  const targetLabel = `${target.target_system}${
    target.target_subtype ? `/${target.target_subtype}` : ""
  }`;

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
          <Link
            to={`/portal/policies/${policyId}`}
            className="text-sm text-brand-600 hover:underline"
          >
            ← Policy
          </Link>
          <h1 className="text-base font-semibold text-slate-900 truncate">
            {targetLabel}
          </h1>
          <ReviewBadge status={target.review_status} />
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-6">
        {err ? (
          <div className="card p-4 text-sm text-red-600">{err}</div>
        ) : null}

        {frozen ? (
          <div className="card p-4 text-sm bg-amber-50 border-l-4 border-amber-500 text-amber-900">
            This policy is published. Targets are frozen — to change this
            Rego, republish via a new version.
          </div>
        ) : null}

        {/* Metadata */}
        <section className="card p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-4">
            Target metadata
          </h2>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <Field label="Target system">{target.target_system}</Field>
            <Field label="Subtype">
              {target.target_subtype ?? <span className="text-slate-400">—</span>}
            </Field>
            <Field label="Generation method">
              {target.generation_method.replace("_", " ")}
            </Field>
            <Field label="Confidence">
              {target.confidence_score === null
                ? "—"
                : target.confidence_score.toFixed(2)}
            </Field>
            <Field label="Current SHA-256">
              <code className="text-[11px] text-slate-700 break-all">
                {target.rego_content_sha256}
              </code>
            </Field>
            <Field label="Published in bundle">
              {target.published_in_bundle_sha ? (
                <code className="text-[11px] text-slate-700 break-all">
                  {target.published_in_bundle_sha}
                </code>
              ) : (
                <span className="text-slate-400">— (never shipped)</span>
              )}
            </Field>
            <Field label="Created">
              {new Date(target.created_at).toLocaleString()}
            </Field>
            <Field label="Policy status">
              <code className="text-xs">{policy.status}</code>
            </Field>
          </dl>
        </section>

        {/* Rego */}
        <section className="card overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-slate-900">
                Rego module
              </h2>
              <p className="text-xs text-slate-500 mt-1">
                Edits re-run <code>opa check</code> server-side and reset
                review status to <em>pending</em>.
              </p>
            </div>
            {!frozen && !editing ? (
              <button
                type="button"
                className="btn-secondary text-sm"
                onClick={() => setEditing(true)}
              >
                Edit
              </button>
            ) : null}
          </div>

          {editing ? (
            <div className="p-6 space-y-3">
              <textarea
                className="w-full h-96 font-mono text-[12px] leading-snug border border-slate-300 rounded p-3"
                value={draftRego}
                onChange={(e) => {
                  setDraftRego(e.target.value);
                  setOpaStderr(null);
                }}
                spellCheck={false}
              />
              {opaStderr ? (
                <pre className="text-[11px] font-mono bg-red-50 text-red-900 border border-red-200 rounded p-3 overflow-x-auto whitespace-pre-wrap">
                  {opaStderr}
                </pre>
              ) : null}
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  className="btn-primary text-sm"
                  onClick={onSaveEdit}
                  disabled={
                    busy !== null ||
                    draftRego.trim() === "" ||
                    draftRego === target.rego_text
                  }
                >
                  {busy === "edit" ? "Validating…" : "Save changes"}
                </button>
                <button
                  type="button"
                  className="btn-secondary text-sm"
                  onClick={onCancelEdit}
                  disabled={busy !== null}
                >
                  Cancel
                </button>
                {draftRego === target.rego_text ? (
                  <span className="text-xs text-slate-400">No changes</span>
                ) : null}
              </div>
            </div>
          ) : (
            <pre className="text-[12px] font-mono leading-snug p-6 overflow-x-auto bg-white whitespace-pre-wrap">
              {target.rego_text}
            </pre>
          )}
        </section>

        {/* Review actions */}
        {!frozen && !editing ? (
          <section className="card p-6 space-y-4">
            <h2 className="text-base font-semibold text-slate-900">
              Review decision
            </h2>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">
                  Approve
                </label>
                <input
                  type="text"
                  placeholder="Reason (optional)"
                  className="w-full text-sm border border-slate-300 rounded px-3 py-2 mb-2"
                  value={approveReason}
                  onChange={(e) => setApproveReason(e.target.value)}
                  maxLength={2000}
                />
                <button
                  type="button"
                  className="btn-primary text-sm"
                  onClick={onApprove}
                  disabled={busy !== null}
                >
                  {busy === "approve" ? "Approving…" : "Approve target"}
                </button>
                <p className="text-xs text-slate-500 mt-2">
                  Approved targets are eligible to ship in the next bundle.
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">
                  Reject
                </label>
                <input
                  type="text"
                  placeholder="Reason (required)"
                  className="w-full text-sm border border-slate-300 rounded px-3 py-2 mb-2"
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  maxLength={2000}
                />
                <button
                  type="button"
                  className="btn-danger text-sm"
                  onClick={onReject}
                  disabled={busy !== null || rejectReason.trim() === ""}
                >
                  {busy === "reject" ? "Rejecting…" : "Reject target"}
                </button>
                <p className="text-xs text-slate-500 mt-2">
                  Rejected targets are excluded from bundles until edited or
                  re-approved.
                </p>
              </div>
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

function ReviewBadge({
  status,
}: {
  status: "pending" | "approved" | "rejected";
}) {
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

// Pulls `detail.stderr` out of a 422 axios error when the server reports
// an `opa check` failure. Returns null for any other shape so the caller
// can fall back to a generic error message.
function extractOpaStderr(e: unknown): string | null {
  if (typeof e !== "object" || e === null) return null;
  const resp = (e as { response?: { status?: number; data?: unknown } })
    .response;
  if (!resp || resp.status !== 422) return null;
  const data = resp.data;
  if (typeof data !== "object" || data === null) return null;
  const detail = (data as { detail?: unknown }).detail;
  if (typeof detail !== "object" || detail === null) return null;
  const stderr = (detail as { stderr?: unknown }).stderr;
  return typeof stderr === "string" ? stderr : null;
}
