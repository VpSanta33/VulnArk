import { apiClient } from './api';
import { LoginRequest, User } from '../types/api';
import {
  isAuthenticatedLogin,
  isLoginChallenge,
  isLoginRebindRequired,
  LoginResult,
  LoginVerification,
} from '../types/auth';

export class AuthService {
  // User login
  async login(credentials: LoginRequest, verification?: LoginVerification): Promise<LoginResult> {
    if (!verification) {
      apiClient.removeToken();
    }

    const response = await apiClient.post<LoginResult>('/login', {
      ...credentials,
      ...(verification && {
        challenge_token: verification.challengeToken,
        ...(verification.totpCode ? { totp_code: verification.totpCode } : {}),
        ...(verification.recoveryCode ? { recovery_code: verification.recoveryCode } : {}),
      }),
    });
    const result = response.data;
    if (!result) throw new Error('登录响应无效，请重试');

    if (isLoginChallenge(result) || isLoginRebindRequired(result)) {
      return result;
    }

    if (!isAuthenticatedLogin(result)) {
      throw new Error('登录响应无效，请重试');
    }

    apiClient.setToken(result.token);
    return result;
  }

  // User logout
  async logout(): Promise<void> {
    try {
      if (this.isAuthenticated()) {
        await apiClient.post('/logout', undefined, {
          // An already revoked/expired session has nothing left to invalidate.
          validateStatus: status => (status >= 200 && status < 300) || status === 401,
        });
      }
    } finally {
      this.clearSession();
    }
  }

  clearSession(): void {
    apiClient.removeToken();
  }

  // Get current user profile
  async getProfile(): Promise<User> {
    const response = await apiClient.get<User>('/profile');
    return response.data!;
  }

  // Update user profile
  async updateProfile(data: Partial<User>): Promise<User> {
    const response = await apiClient.put<User>('/profile', data);
    return response.data!;
  }

  // Check if user is authenticated
  isAuthenticated(): boolean {
    const token = localStorage.getItem('vulnark_token');
    return !!token;
  }

}

export const authService = new AuthService();
