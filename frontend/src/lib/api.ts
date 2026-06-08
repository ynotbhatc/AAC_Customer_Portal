import axios, { AxiosInstance } from "axios";
import type {
  ComplianceResult,
  FrameworkSummary,
  HostSummary,
  ComplianceTrend,
  RemediationItem,
} from "../types/compliance";
import type {
  Bucket,
  CveEvent,
  CveTags,
  Enrollment,
  FeedRun,
  FeedSource,
  FilterPreferences,
  PortalCveItem,
  PortalCveResponse,
  PortalWhoAmI,
  Severity,
  Tenant,
  TenantCreate,
  TenantCveMatch,
  TenantUpdate,
  TokenCreateBody,
  TokenCreated,
  TokenInfo,
  Vendor,
  VendorSubscription,
} from "../types/cve";
import { getAdminToken, getTenantCreds } from "./auth";

const BASE = import.meta.env.VITE_API_URL ?? "/api";

// ── public client (no auth) — for /api/compliance/* read-only ────────
const api = axios.create({ baseURL: BASE, withCredentials: true });

// ── admin client — bearer = PORTAL_ADMIN_TOKEN ───────────────────────
const adminApi: AxiosInstance = axios.create({ baseURL: BASE });
adminApi.interceptors.request.use((cfg) => {
  const t = getAdminToken();
  if (t) cfg.headers.Authorization = `Bearer ${t}`;
  return cfg;
});

// ── tenant client — bearer = token_secret, X-Token-Id = token_id ─────
const tenantApi: AxiosInstance = axios.create({ baseURL: BASE });
tenantApi.interceptors.request.use((cfg) => {
  const c = getTenantCreds();
  if (c) {
    cfg.headers.Authorization = `Bearer ${c.tokenSecret}`;
    cfg.headers["X-Token-Id"] = c.tokenId;
  }
  return cfg;
});

// ── Compliance Results (legacy, no auth) ─────────────────────────────
export const getResults = (params?: {
  hostname?: string;
  framework?: string;
  limit?: number;
}) =>
  api
    .get<ComplianceResult[]>("/compliance/results", { params })
    .then((r) => r.data);

export const getResult = (id: number) =>
  api.get<ComplianceResult>(`/compliance/results/${id}`).then((r) => r.data);

export const getFrameworks = () =>
  api.get<FrameworkSummary[]>("/compliance/frameworks").then((r) => r.data);

export const getHosts = () =>
  api.get<HostSummary[]>("/compliance/hosts").then((r) => r.data);

export const getTrend = (params: {
  hostname?: string;
  framework: string;
  days?: number;
}) =>
  api.get<ComplianceTrend[]>("/compliance/trend", { params }).then((r) => r.data);

export const getRemediationItems = (params?: {
  hostname?: string;
  status?: string;
  severity?: string;
}) =>
  api.get<RemediationItem[]>("/remediation", { params }).then((r) => r.data);

export const updateRemediationStatus = (
  id: string,
  status: RemediationItem["status"]
) => api.patch(`/remediation/${id}`, { status }).then((r) => r.data);

export const downloadReport = async (params: {
  hostname?: string;
  framework: string;
  format: "pdf" | "csv" | "json";
}) => {
  const response = await api.get("/reports/download", {
    params,
    responseType: "blob",
  });
  const url = URL.createObjectURL(response.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = `aac-report-${params.framework}.${params.format}`;
  a.click();
  URL.revokeObjectURL(url);
};

export type AapJobLaunchResponse = {
  job_id: number;
  status: string;
  url: string | null;
  started_at: string | null;
};

export type AapJobStatus = {
  job_id: number;
  status: string;
  terminal: boolean;
  failed: boolean;
  started: string | null;
  finished: string | null;
  elapsed: number | null;
  url: string | null;
};

export const launchAssessment = (params: {
  hostname: string;
  framework: string;
  template_id: number;
}) =>
  api.post<AapJobLaunchResponse>("/aap/launch", params).then((r) => r.data);

export const getAapJobStatus = (jobId: number) =>
  api.get<AapJobStatus>(`/aap/jobs/${jobId}`).then((r) => r.data);

// ── Admin: ping (used to validate the admin token on login) ───────────
export const adminPing = async (): Promise<void> => {
  // No dedicated /admin/ping endpoint; list_tenants with a 1-row probe.
  await adminApi.get("/admin/v1/tenants");
};

// ── Admin: tenants ────────────────────────────────────────────────────
export const listTenants = (includeDeleted = false) =>
  adminApi
    .get<Tenant[]>("/admin/v1/tenants", { params: { include_deleted: includeDeleted } })
    .then((r) => r.data);

export const getTenant = (id: string) =>
  adminApi.get<Tenant>(`/admin/v1/tenants/${id}`).then((r) => r.data);

export const createTenant = (body: TenantCreate) =>
  adminApi.post<Tenant>("/admin/v1/tenants", body).then((r) => r.data);

export const updateTenant = (id: string, body: TenantUpdate) =>
  adminApi.patch<Tenant>(`/admin/v1/tenants/${id}`, body).then((r) => r.data);

export const deleteTenant = (id: string) =>
  adminApi.delete(`/admin/v1/tenants/${id}`).then((r) => r.data);

// ── Admin: tokens ─────────────────────────────────────────────────────
export const listTokens = (tenantId: string, includeRevoked = false) =>
  adminApi
    .get<TokenInfo[]>(`/admin/v1/tenants/${tenantId}/tokens`, {
      params: { include_revoked: includeRevoked },
    })
    .then((r) => r.data);

export const createToken = (tenantId: string, body: TokenCreateBody) =>
  adminApi
    .post<TokenCreated>(`/admin/v1/tenants/${tenantId}/tokens`, body)
    .then((r) => r.data);

export const revokeToken = (
  tenantId: string,
  tokenId: string,
  reason: string
) =>
  adminApi
    .post(`/admin/v1/tenants/${tenantId}/tokens/${tokenId}/revoke`, { reason })
    .then((r) => r.data);

// ── Admin: feeds ──────────────────────────────────────────────────────
export const listFeedRuns = (params?: { source?: FeedSource; limit?: number }) =>
  adminApi
    .get<FeedRun[]>("/admin/v1/feeds/runs", { params })
    .then((r) => r.data);

export const triggerFeedRun = (source: FeedSource) =>
  adminApi
    .post<{ status: string }>(`/admin/v1/feeds/${source}/run`)
    .then((r) => r.data);

export const listCves = (params?: {
  severity?: Severity;
  kev_only?: boolean;
  bucket?: string;
  vendor?: string;
  search?: string;
  limit?: number;
  cursor?: number;
}) =>
  adminApi
    .get<CveEvent[]>("/admin/v1/feeds/cves", { params })
    .then((r) => r.data);

// ── Admin: classification ─────────────────────────────────────────────
export const listBuckets = () =>
  adminApi.get<Bucket[]>("/admin/v1/buckets").then((r) => r.data);

export const listVendors = () =>
  adminApi.get<Vendor[]>("/admin/v1/vendors").then((r) => r.data);

export const getCveTags = (cveId: string) =>
  adminApi.get<CveTags>(`/admin/v1/cves/${cveId}/tags`).then((r) => r.data);

export const tagBucket = (cveId: string, bucketKey: string) =>
  adminApi
    .post(`/admin/v1/cves/${cveId}/tags/buckets/${bucketKey}`)
    .then((r) => r.data);

export const untagBucket = (cveId: string, bucketKey: string) =>
  adminApi
    .delete(`/admin/v1/cves/${cveId}/tags/buckets/${bucketKey}`)
    .then((r) => r.data);

export const tagVendor = (cveId: string, vendorKey: string) =>
  adminApi
    .post(`/admin/v1/cves/${cveId}/tags/vendors/${vendorKey}`)
    .then((r) => r.data);

export const untagVendor = (cveId: string, vendorKey: string) =>
  adminApi
    .delete(`/admin/v1/cves/${cveId}/tags/vendors/${vendorKey}`)
    .then((r) => r.data);

export const runClassifier = (full = false) =>
  adminApi
    .post<{ status: string; full_rebuild: boolean }>("/admin/v1/classify/run", null, {
      params: { full },
    })
    .then((r) => r.data);

// ── Admin: enrollments + preferences + matches per tenant ─────────────
export const listEnrollments = (tenantId: string) =>
  adminApi
    .get<Enrollment[]>(`/admin/v1/tenants/${tenantId}/enrollments`)
    .then((r) => r.data);

export const enrollBucket = (tenantId: string, bucketKey: string) =>
  adminApi
    .post(`/admin/v1/tenants/${tenantId}/enrollments/${bucketKey}`)
    .then((r) => r.data);

export const unenrollBucket = (tenantId: string, bucketKey: string) =>
  adminApi
    .delete(`/admin/v1/tenants/${tenantId}/enrollments/${bucketKey}`)
    .then((r) => r.data);

export const listVendorSubscriptions = (tenantId: string) =>
  adminApi
    .get<VendorSubscription[]>(`/admin/v1/tenants/${tenantId}/vendor-subscriptions`)
    .then((r) => r.data);

export const setVendorSubscription = (
  tenantId: string,
  vendorKey: string,
  allow: boolean
) =>
  adminApi
    .put(`/admin/v1/tenants/${tenantId}/vendor-subscriptions/${vendorKey}`, { allow })
    .then((r) => r.data);

export const removeVendorSubscription = (tenantId: string, vendorKey: string) =>
  adminApi
    .delete(`/admin/v1/tenants/${tenantId}/vendor-subscriptions/${vendorKey}`)
    .then((r) => r.data);

export const getPreferences = (tenantId: string) =>
  adminApi
    .get<FilterPreferences>(`/admin/v1/tenants/${tenantId}/preferences`)
    .then((r) => r.data);

export const setPreferences = (tenantId: string, body: Partial<FilterPreferences>) =>
  adminApi
    .put<FilterPreferences>(`/admin/v1/tenants/${tenantId}/preferences`, body)
    .then((r) => r.data);

export const listMatches = (
  tenantId: string,
  params?: {
    severity?: Severity;
    kev_only?: boolean;
    acknowledged?: boolean;
    suppressed?: boolean;
    limit?: number;
  }
) =>
  adminApi
    .get<TenantCveMatch[]>(`/admin/v1/tenants/${tenantId}/matches`, { params })
    .then((r) => r.data);

export const triggerInventoryPullForTenant = (tenantId: string) =>
  adminApi
    .post<{ status: string }>(`/admin/v1/tenants/${tenantId}/inventory/pull`)
    .then((r) => r.data);

export const triggerMatchForTenant = (tenantId: string) =>
  adminApi
    .post<{ status: string }>(`/admin/v1/tenants/${tenantId}/matches/run`)
    .then((r) => r.data);

// ── Tenant (per-tenant token): portal feed ───────────────────────────
export const portalWhoAmI = (tenantId: string) =>
  tenantApi
    .get<PortalWhoAmI>(`/portal/v1/tenants/${tenantId}/whoami`)
    .then((r) => r.data);

export const portalListCves = (
  tenantId: string,
  params?: {
    since?: string;
    severity?: Severity;
    kev_only?: boolean;
    cursor?: number;
    limit?: number;
    include_acknowledged?: boolean;
    include_suppressed?: boolean;
  }
) =>
  tenantApi
    .get<PortalCveResponse | PortalCveItem[]>(
      `/portal/v1/tenants/${tenantId}/cves`,
      { params }
    )
    .then((r) => r.data);

export const portalAckCve = (tenantId: string, cveId: string) =>
  tenantApi
    .post(`/portal/v1/tenants/${tenantId}/cves/${cveId}/ack`)
    .then((r) => r.data);

export const portalSuppressCve = (
  tenantId: string,
  cveId: string,
  reason: string
) =>
  tenantApi
    .post(`/portal/v1/tenants/${tenantId}/cves/${cveId}/suppress`, { reason })
    .then((r) => r.data);

// ── tenant-USER client — bearer = session_token (portal login) ───────
// Separate axios instance so login/logout/me/policy endpoints inherit
// the bearer through one interceptor without polluting the M2M
// tenantApi above.
const userApi: AxiosInstance = axios.create({ baseURL: BASE });

userApi.interceptors.request.use((cfg) => {
  const s = getUserSession();
  if (s) {
    cfg.headers = cfg.headers ?? {};
    (cfg.headers as Record<string, string>)["Authorization"] =
      `Bearer ${s.sessionToken}`;
  }
  return cfg;
});

// Auto-redirect on session expiry / revocation. Components that want
// to handle 401 themselves can wrap their call in try/catch — the
// global handler runs first so the page transition wins by default.
userApi.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err?.response?.status === 401) {
      clearUserSession();
      if (!window.location.pathname.startsWith("/portal/login")) {
        window.location.href = "/portal/login";
      }
    }
    return Promise.reject(err);
  }
);

import {
  clearUserSession,
  getUserSession,
  setUserSession,
} from "./auth";
import type {
  BackupCodesResponse,
  LoginRequest,
  MeResponse,
  MfaFactorSummary,
  PasswordResetConfirm,
  SessionCreated,
  TotpConfirmRequest,
  TotpSetupResponse,
  TotpVerifyRequest,
} from "../types/user";

export const userLogin = async (body: LoginRequest): Promise<SessionCreated> => {
  const r = await userApi.post<SessionCreated>("/portal/v1/auth/login", body);
  setUserSession({
    sessionToken: r.data.session_token,
    tenantId: body.tenant_id,
    email: body.email,
    expiresAt: r.data.expires_at,
    mfaRequired: r.data.mfa_required,
    mfaVerified: r.data.mfa_verified,
  });
  return r.data;
};

export const userLogout = async (): Promise<void> => {
  try {
    await userApi.post("/portal/v1/me/logout");
  } finally {
    clearUserSession();
  }
};

export const userLogoutAll = async (): Promise<void> => {
  try {
    await userApi.post("/portal/v1/me/logout-all");
  } finally {
    clearUserSession();
  }
};

export const userMe = (): Promise<MeResponse> =>
  userApi.get<MeResponse>("/portal/v1/me").then((r) => r.data);

export const userPasswordResetConfirm = (
  body: PasswordResetConfirm
): Promise<void> =>
  userApi
    .post("/portal/v1/auth/password-reset/confirm", body)
    .then(() => undefined);

// ── MFA (PR 16) ──────────────────────────────────────────────────────

export const userMfaFactors = (): Promise<MfaFactorSummary[]> =>
  userApi.get<MfaFactorSummary[]>("/portal/v1/me/mfa/factors").then((r) => r.data);

export const userMfaTotpSetup = (): Promise<TotpSetupResponse> =>
  userApi.post<TotpSetupResponse>("/portal/v1/me/mfa/totp/setup").then((r) => r.data);

export const userMfaTotpConfirm = (
  body: TotpConfirmRequest
): Promise<BackupCodesResponse> =>
  userApi.post<BackupCodesResponse>("/portal/v1/me/mfa/totp/confirm", body).then((r) => r.data);

export const userMfaRevokeFactor = (factorId: string): Promise<void> =>
  userApi.post(`/portal/v1/me/mfa/factors/${factorId}/revoke`).then(() => undefined);

// Login-time second factor — flips session.mfa_verified=true on success.
// Refreshes the local UserSession so the UI immediately sees the new
// state without forcing a re-login.
export const userTotpVerify = async (body: TotpVerifyRequest): Promise<void> => {
  await userApi.post("/portal/v1/auth/totp/verify", body);
  const s = getUserSession();
  if (s) setUserSession({ ...s, mfaVerified: true });
};

// ── Policies — Path A upload + list + detail + actions (PR 17) ───────

import type {
  CustomerPolicyDetail,
  CustomerPolicySummary,
  IRExtractionResponse,
  RegoGenerationResponse,
  RepublishRequest,
  RepublishResponse,
  TargetDetail,
  TargetEditRequest,
  TargetReviewAction,
  TargetSummary,
  UploadAccepted,
} from "../types/policy";
import type {
  BuildBundleResponse,
  BundleHistoryEntry,
  BundleManifest,
  PublishResponse,
} from "../types/bundle";
import type { AuditLogEntry } from "../types/audit";
import type {
  BaselineIngestRequest,
  BaselineSnapshotDetail,
  BaselineSnapshotSummary,
} from "../types/baseline";

export const userPoliciesList = (params?: {
  framework_bucket?: string;
  status?: string;
}): Promise<CustomerPolicySummary[]> =>
  userApi
    .get<CustomerPolicySummary[]>("/portal/v1/me/policies", { params })
    .then((r) => r.data);

export const userPolicyDetail = (id: string): Promise<CustomerPolicyDetail> =>
  userApi
    .get<CustomerPolicyDetail>(`/portal/v1/me/policies/${id}`)
    .then((r) => r.data);

export const userPolicyUpload = (
  name: string,
  frameworkBucket: string,
  file: File
): Promise<UploadAccepted> => {
  const fd = new FormData();
  fd.append("name", name);
  fd.append("framework_bucket", frameworkBucket);
  fd.append("file", file);
  // Don't set Content-Type — let the browser produce the correct
  // multipart boundary.
  return userApi
    .post<UploadAccepted>("/portal/v1/me/policies/upload", fd)
    .then((r) => r.data);
};

export const userPolicyExtractIr = (id: string): Promise<IRExtractionResponse> =>
  userApi
    .post<IRExtractionResponse>(`/portal/v1/me/policies/${id}/extract-ir`)
    .then((r) => r.data);

export const userPolicyGenerateRego = (
  id: string
): Promise<RegoGenerationResponse> =>
  userApi
    .post<RegoGenerationResponse>(`/portal/v1/me/policies/${id}/generate-rego`)
    .then((r) => r.data);

export const userPolicyTargets = (id: string): Promise<TargetSummary[]> =>
  userApi
    .get<TargetSummary[]>(`/portal/v1/me/policies/${id}/targets`)
    .then((r) => r.data);

export const userPolicyTargetDetail = (
  policyId: string,
  targetId: string
): Promise<TargetDetail> =>
  userApi
    .get<TargetDetail>(`/portal/v1/me/policies/${policyId}/targets/${targetId}`)
    .then((r) => r.data);

export const userPolicyTargetEdit = (
  policyId: string,
  targetId: string,
  body: TargetEditRequest
): Promise<TargetDetail> =>
  userApi
    .patch<TargetDetail>(
      `/portal/v1/me/policies/${policyId}/targets/${targetId}`,
      body
    )
    .then((r) => r.data);

export const userPolicyTargetApprove = (
  policyId: string,
  targetId: string,
  body: TargetReviewAction
): Promise<TargetSummary> =>
  userApi
    .post<TargetSummary>(
      `/portal/v1/me/policies/${policyId}/targets/${targetId}/approve`,
      body
    )
    .then((r) => r.data);

export const userPolicyTargetReject = (
  policyId: string,
  targetId: string,
  body: TargetReviewAction
): Promise<TargetSummary> =>
  userApi
    .post<TargetSummary>(
      `/portal/v1/me/policies/${policyId}/targets/${targetId}/reject`,
      body
    )
    .then((r) => r.data);

// ── Publish + bundle (PR 19/20 of Piece 46) ──────────────────────────

export const userPolicyPublish = (policyId: string): Promise<PublishResponse> =>
  userApi
    .post<PublishResponse>(`/portal/v1/me/policies/${policyId}/publish`)
    .then((r) => r.data);

export const userBundleBuild = (): Promise<BuildBundleResponse> =>
  userApi
    .post<BuildBundleResponse>("/portal/v1/me/bundles/build")
    .then((r) => r.data);

// 404 here is non-exceptional — it just means the tenant hasn't built
// a bundle yet. Callers should catch and render an empty state; we
// keep the axios-default behavior of rejecting on 404 so the
// distinction is explicit at the call site.
export const userBundleCurrentManifest = (): Promise<BundleManifest> =>
  userApi
    .get<BundleManifest>("/portal/v1/me/bundles/current/manifest")
    .then((r) => r.data);

// Cursor-paginated history. Pass the (built_at, bundle_id) PAIR from
// the oldest entry of the prior page to walk back through time. The
// server treats both-or-neither (it 400s on a mismatched pair) — the
// timestamp alone isn't safe because two builds can land in the same
// microsecond. Server caps limit at 200.
export const userBundleHistory = (opts?: {
  limit?: number;
  before_built_at?: string;
  before_id?: string;
}): Promise<BundleHistoryEntry[]> =>
  userApi
    .get<BundleHistoryEntry[]>("/portal/v1/me/bundles", { params: opts })
    .then((r) => r.data);

// Full manifest for an arbitrary historical bundle. Tenant-scoped on
// the server — a foreign-tenant bundle ID 404s identically to a
// non-existent one.
export const userBundleManifestById = (
  bundleId: string
): Promise<BundleManifest> =>
  userApi
    .get<BundleManifest>(`/portal/v1/me/bundles/${bundleId}/manifest`)
    .then((r) => r.data);

// ── Republish (PR 22 of Piece 46) ────────────────────────────────────

// Creates a draft successor to a published policy. Targets are copied
// 1:1; the original is left untouched (immutability is trigger-enforced).
export const userPolicyRepublish = (
  policyId: string,
  body: RepublishRequest
): Promise<RepublishResponse> =>
  userApi
    .post<RepublishResponse>(
      `/portal/v1/me/policies/${policyId}/republish`,
      body
    )
    .then((r) => r.data);

// ── Baselines (Piece 50) ─────────────────────────────────────────────

export const userBaselinesList = (opts?: {
  limit?: number;
  before_captured_at?: string;
  before_id?: string;
}): Promise<BaselineSnapshotSummary[]> =>
  userApi
    .get<BaselineSnapshotSummary[]>("/portal/v1/me/baselines", { params: opts })
    .then((r) => r.data);

export const userBaselineDetail = (
  id: string
): Promise<BaselineSnapshotDetail> =>
  userApi
    .get<BaselineSnapshotDetail>(`/portal/v1/me/baselines/${id}`)
    .then((r) => r.data);

// Manual import path — primarily for backfills and testing. The
// bridge-push endpoint lives on the M2M surface and isn't called
// from the frontend.
export const userBaselineManualImport = (
  body: BaselineIngestRequest
): Promise<BaselineSnapshotDetail> =>
  userApi
    .post<BaselineSnapshotDetail>("/portal/v1/me/baselines", body)
    .then((r) => r.data);

// ── Audit log (PR 21 of Piece 46) ────────────────────────────────────

// Cursor-paginated: pass the smallest id from the prior page as
// before_id to walk back through history. The server caps limit at 200.
export const userPolicyAuditLog = (
  policyId: string,
  opts?: { limit?: number; before_id?: number }
): Promise<AuditLogEntry[]> =>
  userApi
    .get<AuditLogEntry[]>(`/portal/v1/me/policies/${policyId}/audit-log`, {
      params: opts,
    })
    .then((r) => r.data);

// ── Standard library + fork (Path B, PR 18) ──────────────────────────

import type {
  ForkRequest,
  ForkResponse,
  LibraryStats,
  StandardFileContent,
  StandardFileMeta,
  UpstreamDiff,
} from "../types/library";

export const userLibraryStats = (): Promise<LibraryStats> =>
  userApi
    .get<LibraryStats>("/portal/v1/standard-library/stats")
    .then((r) => r.data);

export const userLibraryCategories = (): Promise<string[]> =>
  userApi
    .get<string[]>("/portal/v1/standard-library/categories")
    .then((r) => r.data);

export const userLibraryFiles = (params?: {
  prefix?: string;
  limit?: number;
}): Promise<StandardFileMeta[]> =>
  userApi
    .get<StandardFileMeta[]>("/portal/v1/standard-library/files", { params })
    .then((r) => r.data);

export const userLibraryFile = (path: string): Promise<StandardFileContent> =>
  userApi
    .get<StandardFileContent>("/portal/v1/standard-library/file", {
      params: { path },
    })
    .then((r) => r.data);

export const userPolicyFork = (body: ForkRequest): Promise<ForkResponse> =>
  userApi
    .post<ForkResponse>("/portal/v1/me/policies/fork", body)
    .then((r) => r.data);

export const userPolicyUpstreamDiff = (id: string): Promise<UpstreamDiff> =>
  userApi
    .get<UpstreamDiff>(`/portal/v1/me/policies/${id}/upstream-diff`)
    .then((r) => r.data);

// ── Host mappings (tenant-admin only; P0-A3) ─────────────────────────

import type {
  HostMapping,
  CreateHostMapping,
} from "../types/host-mapping";

export const userHostMappingsList = (): Promise<HostMapping[]> =>
  userApi
    .get<HostMapping[]>("/portal/v1/me/host-mappings")
    .then((r) => r.data);

export const userHostMappingCreate = (
  body: CreateHostMapping
): Promise<HostMapping> =>
  userApi
    .post<HostMapping>("/portal/v1/me/host-mappings", body)
    .then((r) => r.data);

export const userHostMappingDelete = (id: string): Promise<void> =>
  userApi.delete(`/portal/v1/me/host-mappings/${id}`).then(() => undefined);

export default api;
