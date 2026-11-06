import { User } from './api';

export interface LoginChallenge {
  mfa_required: true;
  challenge_token: string;
  expires_at: string;
}

export interface AuthenticatedLogin {
  mfa_required?: false;
  token: string;
  user: User;
  expires_at?: string;
}

export interface LoginRebindRequired {
  mfa_rebind_required: true;
  rebind_token: string;
  expires_at: string;
}

export type LoginResult = LoginChallenge | LoginRebindRequired | AuthenticatedLogin;

export interface LoginVerification {
  challengeToken: string;
  totpCode?: string;
  recoveryCode?: string;
}

export interface TwoFactorSetup {
  secret: string;
  otpauth_url: string;
  qr_code_data_url: string;
  qr_code_url?: string;
  expires_at: string;
}

export interface TwoFactorStatus {
  enabled: boolean;
  pending: boolean;
  needs_rebind: boolean;
  recovery_codes_remaining: number;
}

export interface TwoFactorVerification {
  recovery_codes: string[];
}

export function isLoginChallenge(result: LoginResult): result is LoginChallenge {
  return 'mfa_required' in result && result.mfa_required === true;
}

export function isLoginRebindRequired(result: LoginResult): result is LoginRebindRequired {
  return 'mfa_rebind_required' in result && result.mfa_rebind_required === true;
}

export function isAuthenticatedLogin(result: unknown): result is AuthenticatedLogin {
  if (!result || typeof result !== 'object') return false;
  const candidate = result as Record<string, unknown>;
  return candidate.mfa_required !== true
    && candidate.mfa_rebind_required !== true
    && typeof candidate.token === 'string'
    && candidate.token.length > 0
    && !!candidate.user
    && typeof candidate.user === 'object';
}

export function isExpiredLoginChallengeError(message: string): boolean {
  return /(challenge|挑战).*(expired|过期|无效)|(expired|过期).*(challenge|挑战)/i.test(message);
}

export function getAuthError(error: unknown, fallback: string): { message: string; code?: number } {
  if (!error || typeof error !== 'object') return { message: fallback };
  const value = error as {
    message?: unknown;
    code?: unknown;
    response?: { status?: unknown; data?: { message?: unknown } };
  };
  const responseMessage = value.response?.data?.message;
  const message = typeof responseMessage === 'string'
    ? responseMessage
    : typeof value.message === 'string' ? value.message : fallback;
  const code = typeof value.code === 'number'
    ? value.code
    : typeof value.response?.status === 'number' ? value.response.status : undefined;
  return { message, code };
}
