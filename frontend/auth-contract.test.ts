import {
  isAuthenticatedLogin,
  isExpiredLoginChallengeError,
  isLoginChallenge,
  isLoginRebindRequired,
  LoginResult,
} from './src/types/auth';

const user = {
  id: 1,
  username: 'tester',
  real_name: 'Test User',
  email: 'tester@example.com',
  role: { id: 1, name: 'user' },
};

const assert = (condition: boolean, message: string) => {
  if (!condition) throw new Error(message);
};

const challenge: LoginResult = {
  mfa_required: true,
  challenge_token: 'challenge-token',
  expires_at: '2026-10-28T10:00:00Z',
};
assert(isLoginChallenge(challenge), 'MFA response should be a challenge');
assert(!isAuthenticatedLogin(challenge), 'MFA challenge must not authenticate');

const rebind: LoginResult = {
  mfa_rebind_required: true,
  rebind_token: 'restricted-token',
  expires_at: '2026-10-28T10:00:00Z',
};
assert(isLoginRebindRequired(rebind), 'legacy MFA response should require rebind');
assert(!isAuthenticatedLogin(rebind), 'restricted rebind token must not authenticate');

const authenticated: LoginResult = { token: 'access-token', user };
assert(isAuthenticatedLogin(authenticated), 'token and user should authenticate');
assert(!isAuthenticatedLogin({ token: 'access-token' }), 'token without user must not authenticate');
assert(!isAuthenticatedLogin({ user }), 'user without token must not authenticate');
assert(!isAuthenticatedLogin(null), 'null must not authenticate');
assert(isExpiredLoginChallengeError('挑战已过期或无效'), 'expired challenge should be recognized');
assert(!isExpiredLoginChallengeError('验证码无效'), 'ordinary invalid OTP should remain retryable');

console.log('Authentication response contract assertions passed');
