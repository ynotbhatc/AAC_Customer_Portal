// Mirrors api/src/models/baseline.py.
//
// A baseline snapshot is one tenant's compliance evaluation state at a
// point in time. The bridge POSTs them automatically; an operator can
// also manually import one via the UI for backfills or testing.

export type BaselineSource = "bridge_push" | "manual" | "scheduled";

export interface BaselineFrameworkStats {
  passing: number;
  failing: number;
}

export interface BaselineSummary {
  host_count: number;
  total_evaluations: number;
  passing: number;
  failing: number;
  errors: number;
  by_framework: Record<string, BaselineFrameworkStats>;
}

export interface BaselineIngestRequest {
  bundle_sha256: string;
  summary: BaselineSummary;
  label?: string | null;
}

// List row — lean. summary jsonb is omitted; we project the most-used
// counters out of it server-side so the list payload stays small.
export interface BaselineSnapshotSummary {
  id: string;
  tenant_id: string;
  bundle_sha256: string;
  captured_at: string;
  captured_by_email: string | null;
  label: string | null;
  source: BaselineSource;
  host_count: number;
  passing: number;
  failing: number;
}

export interface BaselineSnapshotDetail extends BaselineSnapshotSummary {
  summary: BaselineSummary;
}
