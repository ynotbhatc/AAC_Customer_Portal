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

// ── Tenant-user session (Phase N+1) ──────────────────────────────────
// The session lives in an HttpOnly cookie that the browser sends
// automatically (axios withCredentials=true on userApi). There is no
// client-readable copy — that's the point: an XSS can no longer
// exfiltrate the session. Auth state is derived from the server via
// GET /api/portal/v1/me; if it 200s, you're authed.
//
// The CSRF cookie is the only part the frontend can read; it's
// echoed via X-CSRF-Token on POST/PATCH/DELETE/PUT (double-submit).
// Prod uses the `__Host-aac_csrf` name; dev uses bare `aac_csrf`.
// The reader tries both and returns whichever is set so the same
// code path works against either environment without a build-time
// flag.
export const readCsrfCookie = (): string | null => {
  const names = ["__Host-aac_csrf", "aac_csrf"];
  for (const name of names) {
    const prefix = name + "=";
    const found = document.cookie
      .split("; ")
      .find((c) => c.startsWith(prefix));
    if (found) return found.slice(prefix.length);
  }
  return null;
};
