// Mirrors the Pydantic + raw query shapes in api/src/routers/*.py
// for the CVE Intelligence multi-tenant feature.

export type Tier = "free" | "standard" | "premium" | "airgapped";
export type TenantStatus = "pending" | "active" | "suspended" | "deleted";
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "NONE";

// ── tenants ──────────────────────────────────────────────────────────
export interface Tenant {
  id: string;
  display_name: string;
  contact_email: string | null;
  tier: Tier;
  aac_bridge_url: string | null;
  aac_bridge_verify_ssl: boolean;
  status: TenantStatus;
  notes: string | null;
  created_at: string;
  updated_at: string;
}

export interface TenantCreate {
  display_name: string;
  contact_email?: string | null;
  tier?: Tier;
  aac_bridge_url?: string | null;
  aac_bridge_verify_ssl?: boolean;
  notes?: string | null;
}

export interface TenantUpdate {
  display_name?: string;
  contact_email?: string | null;
  tier?: Tier;
  aac_bridge_url?: string | null;
  aac_bridge_verify_ssl?: boolean;
  status?: TenantStatus;
  notes?: string | null;
}

// ── tokens ───────────────────────────────────────────────────────────
export interface TokenInfo {
  id: string;
  tenant_id: string;
  token_id: string;
  description: string | null;
  scopes: string[];
  created_at: string;
  created_by: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  revoked_reason: string | null;
}

export interface TokenCreated extends TokenInfo {
  token_secret: string;
}

export interface TokenCreateBody {
  description?: string | null;
  scopes?: string[];
}

// ── feeds (NVD / CISA KEV) ────────────────────────────────────────────
export type FeedSource = "nvd" | "cisa_kev";

export interface FeedRun {
  id: number;
  source: FeedSource | string;
  started_at: string;
  finished_at: string | null;
  status: string;
  cve_count: number | null;
  new_count: number | null;
  updated_count: number | null;
  error_message: string | null;
}

export interface CveEvent {
  cve_id: string;
  cvss_v3: number | null;
  cvss_v3_severity: Severity | null;
  kev_member: boolean;
  kev_date_added: string | null;
  description: string | null;
  published_at: string | null;
  last_modified_at: string | null;
  sources: string[];
}

// ── classification (buckets + vendors) ────────────────────────────────
export type BucketType = "platform" | "domain" | "framework" | "vendor_class" | string;

export interface Bucket {
  id: number;
  key: string;
  display_name: string;
  bucket_type: BucketType;
  sort_order: number;
  active: boolean;
  cve_count: number;
}

export interface Vendor {
  id: number;
  key: string;
  display_name: string;
  aliases: string[] | null;
  cpe_vendor_keys: string[] | null;
  cve_count: number;
  buckets: string[] | null;
}

export interface CveTags {
  cve_id: string;
  buckets: Array<{ key: string; display_name: string; bucket_type: string; method: string }>;
  vendors: Array<{ key: string; display_name: string; method: string }>;
}

// ── enrollments + preferences + matches ───────────────────────────────
export interface Enrollment {
  key: string;
  display_name: string;
  bucket_type: BucketType;
  enrolled_at: string;
}

export interface VendorSubscription {
  vendor_key: string;
  display_name: string;
  allow: boolean;
  updated_at: string;
}

export interface FilterPreferences {
  tenant_id?: string;
  min_severity: Severity;
  deliver_kev_regardless: boolean;
  deliver_tag_only: boolean;
  auto_apply_kev: boolean;
  defaults?: boolean;
}

export interface TenantCveMatch {
  cve_id: string;
  matched_at: string;
  delivered_at: string | null;
  acknowledged_at: string | null;
  suppressed_at: string | null;
  suppressed_reason: string | null;
  cvss_v3: number | null;
  cvss_v3_severity: Severity | null;
  kev_member: boolean;
  description: string | null;
  reason: string | null; // why it matched (bucket key, vendor key, or "kev")
}

// ── portal feed (per-tenant) ─────────────────────────────────────────
export interface PortalWhoAmI {
  tenant_id: string;
  tenant_display_name: string;
  token_id: string;
  scopes: string[];
}

export interface PortalCveItem {
  cve_id: string;
  cvss_v3: number | null;
  cvss_v3_severity: Severity | null;
  kev_member: boolean;
  description: string | null;
  matched_at: string;
  acknowledged_at: string | null;
  suppressed_at: string | null;
  references?: Array<{ url: string; source: string }>;
  remediations?: Array<{ vendor: string; advisory_url: string | null; fixed_version: string | null }>;
}

export interface PortalCveResponse {
  tenant_id: string;
  count: number;
  next_cursor: number | null;
  items: PortalCveItem[];
}
