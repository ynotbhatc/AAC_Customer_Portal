// Token storage. Two separate keys so an admin can also impersonate a
// tenant in the same browser session without one wiping the other.
const ADMIN_KEY = "aac.adminToken";
const TENANT_KEY = "aac.tenantCreds"; // JSON: { tenantId, tokenId, tokenSecret }

export interface TenantCreds {
  tenantId: string;
  tokenId: string;
  tokenSecret: string;
}

export const getAdminToken = (): string | null =>
  localStorage.getItem(ADMIN_KEY);

export const setAdminToken = (t: string): void => {
  localStorage.setItem(ADMIN_KEY, t);
};

export const clearAdminToken = (): void => {
  localStorage.removeItem(ADMIN_KEY);
};

export const getTenantCreds = (): TenantCreds | null => {
  const raw = localStorage.getItem(TENANT_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as TenantCreds;
  } catch {
    return null;
  }
};

export const setTenantCreds = (creds: TenantCreds): void => {
  localStorage.setItem(TENANT_KEY, JSON.stringify(creds));
};

export const clearTenantCreds = (): void => {
  localStorage.removeItem(TENANT_KEY);
};

// ── Tenant-user session (Path-A/B portal login, PR 11+) ─────────────
// Stored separately from the M2M tenant_token credentials so a tenant
// user can open the policy portal and the CVE feed UI in the same browser
// session without one auth context wiping the other.

const USER_SESSION_KEY = "aac.userSession";

export interface UserSession {
  sessionToken: string;        // "{session_id}.{secret}" combined token
  tenantId: string;            // surfaced for headers / display
  email: string;
  expiresAt: string;           // ISO 8601 — UI uses to soft-expire locally
  mfaRequired: boolean;
  mfaVerified: boolean;
}

export const getUserSession = (): UserSession | null => {
  const raw = localStorage.getItem(USER_SESSION_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as UserSession;
  } catch {
    return null;
  }
};

export const setUserSession = (s: UserSession): void => {
  localStorage.setItem(USER_SESSION_KEY, JSON.stringify(s));
};

export const clearUserSession = (): void => {
  localStorage.removeItem(USER_SESSION_KEY);
};
