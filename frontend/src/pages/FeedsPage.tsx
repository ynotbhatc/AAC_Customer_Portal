import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listFeedRuns, runClassifier, triggerFeedRun } from "../lib/api";
import { extractErr, relTime } from "../lib/utils";

export default function FeedsPage() {
  const qc = useQueryClient();
  const { data, isLoading, error } = useQuery({
    queryKey: ["feed-runs", "all"],
    queryFn: () => listFeedRuns({ limit: 50 }),
  });

  const nvd = useMutation({
    mutationFn: () => triggerFeedRun("nvd"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["feed-runs"] }),
  });
  const kev = useMutation({
    mutationFn: () => triggerFeedRun("cisa_kev"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["feed-runs"] }),
  });
  const classify = useMutation({
    mutationFn: () => runClassifier(false),
  });
  const classifyFull = useMutation({
    mutationFn: () => runClassifier(true),
  });

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Feeds & CVE ingest</h1>
          <p className="text-sm text-slate-500 mt-1">
            Trigger an NVD or CISA KEV pull, then run the classifier to tag new CVEs.
          </p>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <FeedCard
          title="NVD"
          desc="National Vulnerability Database — full CVE catalog."
          onRun={() => nvd.mutate()}
          pending={nvd.isPending}
          error={nvd.error}
        />
        <FeedCard
          title="CISA KEV"
          desc="Known Exploited Vulnerabilities catalog."
          onRun={() => kev.mutate()}
          pending={kev.isPending}
          error={kev.error}
        />
      </div>

      <div className="card p-5">
        <div className="flex items-center justify-between">
          <div>
            <div className="font-semibold">Classifier</div>
            <p className="text-sm text-slate-500 mt-1">
              Tag CVEs with buckets and vendors. Full rebuild re-tags everything.
            </p>
          </div>
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={() => classify.mutate()}>
              {classify.isPending ? "Running…" : "Classify new"}
            </button>
            <button className="btn-secondary" onClick={() => classifyFull.mutate()}>
              {classifyFull.isPending ? "Rebuilding…" : "Full rebuild"}
            </button>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="px-4 py-3 border-b border-slate-200">
          <h2 className="font-semibold">Recent feed runs</h2>
        </div>
        {isLoading && <div className="p-4 text-slate-500">Loading…</div>}
        {error && (
          <div className="p-4 text-red-700 text-sm">{extractErr(error)}</div>
        )}
        {data && (
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-xs uppercase text-slate-600">
              <tr>
                <th className="text-left px-4 py-2">Source</th>
                <th className="text-left px-4 py-2">Started</th>
                <th className="text-left px-4 py-2">Finished</th>
                <th className="text-left px-4 py-2">Status</th>
                <th className="text-right px-4 py-2">Total / new / updated</th>
                <th className="text-left px-4 py-2">Error</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200">
              {data.map((r) => (
                <tr key={r.id}>
                  <td className="px-4 py-2 font-medium">{r.source}</td>
                  <td className="px-4 py-2 text-xs text-slate-500">{relTime(r.started_at)}</td>
                  <td className="px-4 py-2 text-xs text-slate-500">{relTime(r.finished_at)}</td>
                  <td className="px-4 py-2">{r.status}</td>
                  <td className="px-4 py-2 text-right text-xs">
                    {r.cve_count ?? 0} / {r.new_count ?? 0} / {r.updated_count ?? 0}
                  </td>
                  <td className="px-4 py-2 text-xs text-red-700">
                    {r.error_message ?? ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function FeedCard({
  title,
  desc,
  onRun,
  pending,
  error,
}: {
  title: string;
  desc: string;
  onRun: () => void;
  pending: boolean;
  error: unknown;
}) {
  return (
    <div className="card p-5">
      <div className="font-semibold text-lg">{title}</div>
      <p className="text-sm text-slate-500 mt-1">{desc}</p>
      {error ? (
        <div className="mt-2 text-sm text-red-700">{extractErr(error)}</div>
      ) : null}
      <button className="btn-primary mt-3" onClick={onRun} disabled={pending}>
        {pending ? "Triggering…" : `Run ${title}`}
      </button>
    </div>
  );
}
