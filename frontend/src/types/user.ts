// TypeScript types mirroring the Pydantic models in
// api/src/models/tenant_session.py and tenant_user.py.

export type Role = "account_owner" | "editor" | "viewer";

export interface LoginRequest {
  tenant_id: string;
  email: string;
  password: string;
}

export interface SessionCreated {
  session_token: string;       // bridge sends as Authorization: Bearer
  expires_at: string;          // ISO 8601
  mfa_required: boolean;
  mfa_verified: boolean;
}

export interface MeResponse {
  tenant_id: string;
  user_id: string;
  email: string;
  display_name: string | null;
  role: Role;
  mfa_required: boolean;
  mfa_verified: boolean;
}

export interface PasswordResetConfirm {
  reset_token: string;
  new_password: string;
}

export interface LogoutResult {
  revoked: "session" | "all";
}
