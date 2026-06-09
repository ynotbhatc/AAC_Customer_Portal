/**
 * Tenant permission audit types. Mirrors the response shape of
 * GET /portal/v1/me/permissions — see api/src/routers/permissions.py.
 */

export interface PermissionUser {
  tenant_user_id: string;
  email: string;
  display_name: string | null;
  role: "viewer" | "editor" | "account_owner";
  self: boolean;
}

export interface RoleCapability {
  name: "viewer" | "editor" | "account_owner";
  description: string;
  capabilities: string[];
}

export interface PermissionsResponse {
  users: PermissionUser[];
  roles: RoleCapability[];
}
