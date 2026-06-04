import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { userLibraryFile, userPolicyFork } from "../lib/api";
import { extractErr } from "../lib/utils";
import type { StandardFileContent } from "../types/library";

/**
 * One standard library file's preview + Fork action.
 *
 * The fork creates a customer overlay row (policy_source='forked_overlay')
 * with the upstream Rego copied verbatim into customer_policy_targets.
 * The customer can then edit it via the per-target review screen
 * (PR 19), and `upstream-diff` will show their changes against the
 * pinned upstream version.
 *
 * Path comes from the ?path= query string. The library indexer's
 * membership check on the API side prevents directory traversal.
 */
export default function PortalLibraryFilePage() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const path = params.get("path") ?? "";

  const [file, setFile] = useState<StandardFileContent | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // Fork form
  const [name, setName] = useState("");
  const [bucket, setBucket] = useState("");
  const [forking, setForking] = useState(false);
  const [forkErr, setForkErr] = useState<string | null>(null);

  useEffect(() => {
    if (!path) {
      setErr("Missing ?path query parameter.");
      return;
    }
    userLibraryFile(path)
      .then((f) => {
        setFile(f);
        // Seed the form: name = file's package, framework = first
        // path segment. Customer can edit both.
        setName(f.package_name || path.split("/").pop()?.replace(".rego", "") || "");
        setBucket(path.split("/")[0] || "");
      })
      .catch((e) => setErr(extractErr(e)));
  }, [path]);

  const onFork = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setForking(true);
    setForkErr(null);
    try {
      const result = await userPolicyFork({
        standard_library_path: file.path,
        framework_bucket: bucket.trim(),
        name: name.trim(),
      });
      navigate(`/portal/policies/${result.customer_policy_id}`, {
        replace: true,
      });
    } catch (e2) {
      setForkErr(extractErr(e2));
    } finally {
      setForking(false);
    }
  };

  if (err) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center text-red-600 text-sm">
        {err}
      </div>
    );
  }
  if (!file) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center text-slate-500 text-sm">
        Loading…
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-4">
          <Link
            to="/portal/library"
            className="text-sm text-brand-600 hover:underline"
          >
            ← Library
          </Link>
          <h1 className="text-base font-semibold text-slate-900 font-mono text-sm truncate">
            {file.path}
          </h1>
          <span className="ml-auto text-xs text-slate-500">
            sha {file.sha256.slice(0, 12)}…
          </span>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-6 space-y-6">
        {/* Rego preview */}
        <section className="card overflow-hidden">
          <div className="px-4 py-2 bg-slate-50 text-xs text-slate-500 border-b border-slate-200 flex justify-between">
            <span>Package <code>{file.package_name || "—"}</code></span>
            <span>{(file.bytes_size / 1024).toFixed(1)} KB</span>
          </div>
          <pre className="text-xs font-mono p-4 overflow-x-auto leading-relaxed text-slate-800 bg-white max-h-[60vh]">
            {file.rego_text}
          </pre>
        </section>

        {/* Fork form */}
        <section className="card p-6">
          <h2 className="text-base font-semibold text-slate-900 mb-1">
            Fork as customer overlay
          </h2>
          <p className="text-sm text-slate-500 mb-4">
            Creates a customer overlay row with this Rego copied verbatim.
            You can edit it from the policy detail page, and the upstream
            diff will track your changes against the pinned library version{" "}
            <code className="text-xs">{file.sha256.slice(0, 10)}…</code>.
          </p>

          <form onSubmit={onFork} className="space-y-4">
            <div>
              <label className="label">Policy name</label>
              <input
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                maxLength={255}
              />
            </div>

            <div>
              <label className="label">Framework bucket</label>
              <input
                className="input font-mono text-xs"
                value={bucket}
                onChange={(e) => setBucket(e.target.value)}
                required
                maxLength={128}
              />
              <p className="text-xs text-slate-500 mt-1">
                Defaults to the source path's category. Override to re-
                categorize within your library.
              </p>
            </div>

            {forkErr ? (
              <div className="text-sm text-red-600">{forkErr}</div>
            ) : null}

            <button
              type="submit"
              className="btn-primary"
              disabled={forking || !name.trim() || !bucket.trim()}
            >
              {forking ? "Forking…" : "Fork into my library"}
            </button>
          </form>
        </section>
      </main>
    </div>
  );
}
