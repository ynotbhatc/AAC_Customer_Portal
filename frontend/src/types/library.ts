// TypeScript types mirroring api/src/models/standard_library.py and the
// Path B fields on customer_policy.py.

export interface LibraryStats {
  file_count: number;
  category_count: number;
  library_version: string;
}

export interface StandardFileMeta {
  path: string;
  bytes_size: number;
  sha256: string;
  package_name: string;
}

export interface StandardFileContent extends StandardFileMeta {
  rego_text: string;
}

export interface ForkRequest {
  standard_library_path: string;
  framework_bucket: string;
  name: string;
}

export interface ForkResponse {
  customer_policy_id: string;
  customer_policy_target_id: string;
  parent_standard_ref: string;
  parent_standard_version: string;
  target_system: string;
}

export interface UpstreamDiff {
  customer_policy_id: string;
  parent_standard_ref: string;
  parent_standard_version: string;
  current_upstream_sha256: string;
  fork_sha256: string;
  overlay_sha256: string;
  upstream_changed_since_fork: boolean;
  unified_diff: string;
}
