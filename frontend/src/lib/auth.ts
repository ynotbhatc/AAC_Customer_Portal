/**
 * OIDC auth helpers — wraps keycloak-js with React-friendly utilities.
 *
 * Usage:
 *   import { initAuth, getToken, getUserInfo } from "./auth";
 *
 *   // In main.tsx — call before rendering app
 *   await initAuth();
 *
 *   // In API client — attach bearer token to every request
 *   api.interceptors.request.use(async (config) => {
 *     config.headers.Authorization = `Bearer ${await getToken()}`;
 *     return config;
 *   });
 */
import keycloak from "./keycloak";

export interface UserInfo {
  sub: string;
  preferred_username: string;
  email: string;
  name: string;
  roles: string[];
}

/**
 * Initialize Keycloak SSO. Attempts silent SSO first; falls back to login redirect.
 * Call once before rendering the React app.
 */
export async function initAuth(): Promise<boolean> {
  const authenticated = await keycloak.init({
    onLoad: "login-required",
    silentCheckSsoRedirectUri: window.location.origin + "/silent-check-sso.html",
    pkceMethod: "S256",
    checkLoginIframe: false,
  });

  // Auto-refresh token 60 seconds before expiry
  setInterval(async () => {
    try {
      await keycloak.updateToken(60);
    } catch {
      keycloak.login();
    }
  }, 30_000);

  return authenticated;
}

/**
 * Return a valid access token, refreshing if needed.
 */
export async function getToken(): Promise<string> {
  await keycloak.updateToken(30);
  return keycloak.token ?? "";
}

/**
 * Decoded user info from the JWT token.
 */
export function getUserInfo(): UserInfo | null {
  if (!keycloak.tokenParsed) return null;
  const t = keycloak.tokenParsed as Record<string, unknown>;
  return {
    sub: t.sub as string,
    preferred_username: t.preferred_username as string,
    email: t.email as string,
    name: t.name as string,
    roles: (t.realm_access as { roles: string[] })?.roles ?? [],
  };
}

export function logout() {
  keycloak.logout({ redirectUri: window.location.origin });
}

export { keycloak };
