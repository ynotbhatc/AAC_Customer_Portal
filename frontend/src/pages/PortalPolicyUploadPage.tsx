import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { userPolicyUpload } from "../lib/api";
import { extractErr } from "../lib/utils";

/**
 * Path A — upload a prose policy document (PDF / DOCX / Markdown /
 * HTML / plain text).
 *
 * After successful upload, navigates to the policy detail page where
 * the user can trigger IR extraction + Rego generation. We don't
 * pre-fire those steps here because they cost LLM tokens — let the
 * user decide.
 */
export default function PortalPolicyUploadPage() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [bucket, setBucket] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setErr("Pick a file first.");
      return;
    }
    setErr(null);
    setBusy(true);
    try {
      const result = await userPolicyUpload(name.trim(), bucket.trim(), file);
      navigate(`/portal/policies/${result.customer_policy_id}`, {
        replace: true,
      });
    } catch (e2) {
      setErr(extractErr(e2));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-3xl mx-auto px-4 py-3 flex items-center gap-4">
          <Link
            to="/portal/policies"
            className="text-sm text-brand-600 hover:underline"
          >
            ← Policies
          </Link>
          <h1 className="text-base font-semibold text-slate-900">
            Upload a policy
          </h1>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-4 py-6">
        <form onSubmit={onSubmit} className="card p-6 space-y-4">
          <div>
            <label className="label">Policy name</label>
            <input
              className="input"
              placeholder="Acme Password Standard"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              maxLength={255}
            />
            <p className="text-xs text-slate-500 mt-1">
              Customer-facing title. You can rename later via republish.
            </p>
          </div>

          <div>
            <label className="label">Framework bucket</label>
            <input
              className="input font-mono text-xs"
              placeholder="corporate"
              value={bucket}
              onChange={(e) => setBucket(e.target.value)}
              required
              maxLength={128}
            />
            <p className="text-xs text-slate-500 mt-1">
              Where this policy will appear in your library. Common values:{" "}
              <code>corporate</code>, <code>cis_rhel9</code>, <code>iso27001</code>,{" "}
              <code>nist_800_53</code>, <code>pci_dss</code>.
            </p>
          </div>

          <div>
            <label className="label">Policy document</label>
            <input
              className="input"
              type="file"
              accept=".pdf,.docx,.md,.markdown,.html,.htm,.txt,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/markdown,text/html,text/plain"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              required
            />
            <p className="text-xs text-slate-500 mt-1">
              PDF, DOCX, Markdown, HTML, or plain text. Up to 15 MB. The
              server detects the format from the file bytes, not the
              extension — a .txt file with a PDF inside still parses as
              PDF.
            </p>
          </div>

          {err ? <div className="text-sm text-red-600">{err}</div> : null}

          <div className="flex items-center gap-3">
            <button
              type="submit"
              className="btn-primary"
              disabled={busy || !file || !name.trim() || !bucket.trim()}
            >
              {busy ? "Uploading…" : "Upload"}
            </button>
            <Link to="/portal/policies" className="btn-secondary">
              Cancel
            </Link>
          </div>
        </form>

        <div className="text-xs text-slate-500 mt-4 leading-relaxed">
          After upload, the document is parsed to plaintext and the
          policy enters <code>draft</code> status. You then trigger IR
          extraction (LLM) and Rego generation (template + LLM fallback)
          from the policy detail page. None of these run automatically —
          they cost LLM tokens, so you stay in control.
        </div>
      </main>
    </div>
  );
}
