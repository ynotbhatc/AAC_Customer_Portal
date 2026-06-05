// TypeScript types mirroring api/src/models/customer_policy.py and
// api/src/models/target_review.py. Only the fields the UI consumes
// are typed — fields like control_owner_user_id (Tier 1 governance,
// Phase 7+) aren't exposed yet.

export type PolicySource =
  | "prose_upload"
  | "forked_overlay"
  | "customer_original";

export type PolicyStatus = "draft" | "in_review" | "published" | "archived";

export type GenerationMethod =
  | "template_mapped"
  | "llm_fallback"
  | "customer_authored";

export type ReviewStatus = "pending" | "approved" | "rejected";

export interface CustomerPolicySummary {
  id: string;
  tenant_id: string;
  name: string;
  framework_bucket: string;
  policy_source: PolicySource;
  version_semver: string;
  effective_date: string | null;
  status: PolicyStatus;
  created_at: string;
  updated_at: string;
}

export interface CustomerPolicyDetail extends CustomerPolicySummary {
  source_file_storage_key: string | null;
  source_file_mime: string | null;
  parent_standard_ref: string | null;
  parent_standard_version: string | null;
  ir_json: Record<string, unknown> | null;
}

export interface UploadAccepted {
  customer_policy_id: string;
  upload_id: string;
  original_filename: string;
  sniffed_mime: string;
  byte_size: number;
  extracted_text_chars: number;
}

export interface IRExtractionResponse {
  customer_policy_id: string;
  schema_version: string;
  control_count: number;
  controls_matched_library: number;
  controls_freeform: number;
  ir_json: Record<string, unknown>;
}

export interface GeneratedTargetSummary {
  customer_policy_target_id: string;
  target_system: string;
  target_subtype: string | null;
  generation_method: GenerationMethod;
  confidence_score: number | null;
  review_status: ReviewStatus;
  opa_check_ok: boolean;
  rego_storage_key: string;
  rego_content_sha256: string;
  llm_attempts: number;
  model: string | null;
  opa_check_stderr: string | null;
}

export interface RegoGenerationResponse {
  customer_policy_id: string;
  targets_generated: number;
  targets_pending_review: number;
  targets_rejected: number;
  targets: GeneratedTargetSummary[];
}

export interface TargetSummary {
  id: string;
  customer_policy_id: string;
  target_system: string;
  target_subtype: string | null;
  generation_method: GenerationMethod;
  confidence_score: number | null;
  review_status: ReviewStatus;
  rego_content_sha256: string;
  published_in_bundle_sha: string | null;
  created_at: string;
}

export interface TargetDetail extends TargetSummary {
  rego_storage_key: string;
  rego_text: string;
}

export interface TargetEditRequest {
  rego_text: string;
}

// Reason is optional on the wire (Pydantic accepts null), but the UI
// requires it for /reject and treats it as optional for /approve.
export interface TargetReviewAction {
  reason?: string | null;
}

export interface RepublishRequest {
  // Optional override. Omit to let the server bump the patch
  // component of the parent version automatically.
  new_version_semver?: string | null;
}

export interface RepublishResponse {
  new_customer_policy_id: string;
  new_version_semver: string;
  targets_copied: number;
  parent_policy_id: string;
  parent_version_semver: string;
}
