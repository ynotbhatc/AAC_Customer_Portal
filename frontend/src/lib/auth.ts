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
