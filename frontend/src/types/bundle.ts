// TypeScript types mirroring api/src/models/policy_bundle.py.
// The bundle is what ships to the AAC bridge — the bridge polls
// /tenants/{id}/bundles/current and we sign the envelope so the
// bridge can verify what it loaded. The UI only ever touches the
// manifest + build endpoints; raw bundle bytes are bridge-side.

export interface PublishResponse {
  customer_policy_id: string;
  status: string;
  published_at: string;
  version_semver: string;
}

export interface BuildBundleResponse {
  bundle_id: string;
  bundle_sha256: string;
  bundle_byte_size: number;
  target_count: number;
  excluded_target_count: number;
  customer_policy_ids: string[];
  built_at: string;
  signing_key_id: string;
}

// Each entry in BundleManifest.excluded_targets_log — shape mirrors
// what build_tenant_bundle writes when an approved target is skipped
// (e.g. opa_check_failed_at_build_time).
export interface ExcludedTargetEntry {
  target_id: string;
  target_system: string;
  target_subtype: string | null;
  reason: string;
}

export interface BundleManifest {
  bundle_id: string;
  tenant_id: string;
  bundle_sha256: string;
  bundle_byte_size: number;
  target_count: number;
  customer_policy_ids: string[];
  excluded_target_count: number;
  excluded_targets_log: ExcludedTargetEntry[];
  built_at: string;
  signing_key_id: string;
  // Free-form per-target metadata from the builder. Rendered as a
  // collapsible JSON tree on the bundles page; not strictly typed
  // here because the schema is the builder's contract, not the UI's.
  manifest: Record<string, unknown>;
}
