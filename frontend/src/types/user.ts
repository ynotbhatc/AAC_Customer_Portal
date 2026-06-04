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
  mfa_enrolled: boolean;
  mfa_verified: boolean;
}

export interface PasswordResetConfirm {
  reset_token: string;
  new_password: string;
}

export interface LogoutResult {
  revoked: "session" | "all";
}

// ── MFA (PR 16) ──────────────────────────────────────────────────────

export type FactorType = "totp" | "webauthn" | "backup_codes";

export interface MfaFactorSummary {
  id: string;
  factor_type: FactorType;
  factor_label: string | null;
  enrolled_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface TotpSetupResponse {
  factor_id: string;
  otpauth_uri: string;
  secret: string;
}

export interface TotpConfirmRequest {
  factor_id: string;
  code: string;
}

export interface BackupCodesResponse {
  backup_codes: string[];
}

export interface TotpVerifyRequest {
  code: string;
}
