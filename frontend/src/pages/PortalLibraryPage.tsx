import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  userLibraryCategories,
  userLibraryFiles,
  userLibraryStats,
} from "../lib/api";
import { extractErr } from "../lib/utils";
import type { LibraryStats, StandardFileMeta } from "../types/library";

/**
 * Path B browse — lists every .rego file in the operator-shipped
 * standard library snapshot. Two filters: category (top-level dir)
 * + prefix substring. Click-through to the per-file viewer where
 * the customer can preview and fork.
 *
 * The library is the same content for every tenant; we still gate
 * via require_tenant_user (login required) but no MFA — read-only.
 */
export default function PortalLibraryPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<LibraryStats | null>(null);
  const [categories, setCategories] = useState<string[]>([]);
  const [category, setCategory] = useState("");
  const [pathFilter, setPathFilter] = useState("");
  const [files, setFiles] = useState<StandardFileMeta[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Stats + categories load once.
  useEffect(() => {
    Promise.all([userLibraryStats(), userLibraryCategories()])
      .then(([s, c]) => {
        setStats(s);
        setCategories(c);
      })
      .catch((e) => setErr(extractErr(e)));
  }, []);

  // File list updates when category changes (server-side prefix
  // filter). The pathFilter is a client-side substring narrow.
  useEffect(() => {
    setBusy(true);
    userLibraryFiles({ prefix: category || undefined, limit: 1000 })
      .then(setFiles)
      .catch((e) => setErr(extractErr(e)))
      .finally(() => setBusy(false));
  }, [category]);

  const filtered = useMemo(() => {
    if (!pathFilter) return files;
    const q = pathFilter.toLowerCase();
    return files.filter((f) => f.path.toLowerCase().includes(q));
  }, [files, pathFilter]);

  return (
    <div className="min-h-screen bg-slate-100">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4">
          <Link
            to="/portal/me"
            className="text-sm text-brand-600 hover:underline"
          >
            ← Home
          </Link>
          <h1 className="text-base font-semibold text-slate-900">
            Standard library
          </h1>
          {stats ? (
            <span className="text-xs text-slate-500 ml-auto">
              {stats.file_count} files · version{" "}
              <code className="text-[10px]">{stats.library_version}</code>
            </span>
          ) : null}
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6 space-y-4">
        <div className="card p-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="label">Category</label>
              <select
                className="input"
                value={category}
                onChange={(e) => setCategory(e.target.value)}
              >
                <option value="">All</option>
                {categories.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
            <div className="sm:col-span-2">
              <label className="label">Path contains</label>
              <input
                className="input font-mono text-xs"
                placeholder="e.g. cis_rhel9 / nerc_cip / linux"
                value={pathFilter}
                onChange={(e) => setPathFilter(e.target.value)}
              />
            </div>
          </div>
        </div>

        {err ? (
          <div className="card p-4 text-sm text-red-600">{err}</div>
        ) : null}

        <div className="card overflow-hidden">
          <div className="px-4 py-2 bg-slate-50 text-xs text-slate-500 border-b border-slate-200">
            {busy
              ? "Loading…"
              : `${filtered.length.toLocaleString()} file${filtered.length === 1 ? "" : "s"}`}
          </div>
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-slate-600">
              <tr>
                <th className="text-left px-4 py-2 font-medium">Path</th>
                <th className="text-left px-4 py-2 font-medium">Package</th>
                <th className="text-right px-4 py-2 font-medium">Size</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 500).map((f) => (
                <tr
                  key={f.path}
                  className="border-t border-slate-100 hover:bg-slate-50 cursor-pointer"
                  onClick={() =>
                    navigate(
                      `/portal/library/file?path=${encodeURIComponent(f.path)}`
                    )
                  }
                >
                  <td className="px-4 py-2 font-mono text-xs text-slate-900 truncate max-w-[440px]">
                    {f.path}
                  </td>
                  <td className="px-4 py-2 font-mono text-[11px] text-slate-700">
                    {f.package_name || <span className="text-slate-400">—</span>}
                  </td>
                  <td className="px-4 py-2 text-right text-xs text-slate-500">
                    {(f.bytes_size / 1024).toFixed(1)} KB
                  </td>
                </tr>
              ))}
              {filtered.length > 500 ? (
                <tr>
                  <td
                    colSpan={3}
                    className="px-4 py-3 text-center text-xs text-slate-500 bg-slate-50"
                  >
                    Showing first 500 of {filtered.length}. Narrow with a
                    category or substring filter.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
