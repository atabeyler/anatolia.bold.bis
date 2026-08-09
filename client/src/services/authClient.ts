import { apiClient } from './apiClient';

export interface PublicUser {
  id: string;
  userCode: string;
  email: string | null;
  role: string;
  firstName: string;
  lastName: string;
}

interface LoginResponse {
  accessToken: string;
  user: PublicUser;
  recoveryCodes?: string[];
}

interface MfaChallengeResponse {
  mfaRequired: true;
  mfaToken: string;
  userCode: string;
}

interface MfaEnrollmentRequiredResponse {
  mfaEnrollmentRequired: true;
  mfaToken: string;
  userCode: string;
}

export type LoginOutcome = LoginResponse | MfaChallengeResponse | MfaEnrollmentRequiredResponse;

export function isMfaChallenge(outcome: LoginOutcome): outcome is MfaChallengeResponse {
  return 'mfaRequired' in outcome;
}

export function isMfaEnrollmentRequired(outcome: LoginOutcome): outcome is MfaEnrollmentRequiredResponse {
  return 'mfaEnrollmentRequired' in outcome;
}

export interface MfaEnrollmentStart {
  secret: string;
  otpauthUrl: string;
}

export interface RegisterPayload {
  firstName: string;
  lastName: string;
  nationalId: string;
  email: string;
  password: string;
  userCode: string;
}

export async function login(userCode: string, password: string): Promise<LoginOutcome> {
  const { data } = await apiClient.post<LoginOutcome>('/v1/auth/login', { userCode, password });
  return data;
}

// Voluntary MFA management for an already-authenticated user.
export async function mfaEnrollStart(): Promise<MfaEnrollmentStart> {
  const { data } = await apiClient.post<MfaEnrollmentStart>('/v1/auth/mfa/enroll');
  return data;
}

export async function mfaEnrollConfirm(code: string): Promise<{ recoveryCodes: string[] }> {
  const { data } = await apiClient.post<{ recoveryCodes: string[] }>('/v1/auth/mfa/enroll/confirm', { code });
  return data;
}

export async function mfaDisable(password: string, code: string): Promise<void> {
  await apiClient.post('/v1/auth/mfa/disable', { password, code });
}

// Login-time challenge — completes (or, for a required role with no prior
// enrollment, first sets up) MFA and only then issues a session.
export async function mfaChallengeEnroll(mfaToken: string): Promise<MfaEnrollmentStart> {
  const { data } = await apiClient.post<MfaEnrollmentStart>('/v1/auth/mfa/challenge/enroll', { mfaToken });
  return data;
}

export async function mfaChallengeEnrollConfirm(mfaToken: string, code: string): Promise<LoginResponse> {
  const { data } = await apiClient.post<LoginResponse>('/v1/auth/mfa/challenge/enroll/confirm', {
    mfaToken,
    code,
  });
  return data;
}

export async function mfaChallengeVerify(mfaToken: string, code: string): Promise<LoginResponse> {
  const { data } = await apiClient.post<LoginResponse>('/v1/auth/mfa/challenge/verify', { mfaToken, code });
  return data;
}

interface RegisterResponse {
  messageKey: string;
  registrationTrackingToken: string;
}

export async function register(payload: RegisterPayload): Promise<string> {
  const { data } = await apiClient.post<RegisterResponse>('/v1/auth/register', payload);
  return data.registrationTrackingToken;
}

export async function refresh(): Promise<LoginResponse> {
  const { data } = await apiClient.post<LoginResponse>('/v1/auth/refresh');
  return data;
}

export async function logout(): Promise<void> {
  await apiClient.post('/v1/auth/logout');
}

export async function logoutAll(): Promise<void> {
  await apiClient.post('/v1/auth/logout-all');
}

export async function forgotPassword(identifier: string): Promise<void> {
  await apiClient.post('/v1/auth/forgot-password', { identifier });
}

export async function resetPassword(token: string, newPassword: string): Promise<void> {
  await apiClient.post('/v1/auth/reset-password', { token, newPassword });
}

export async function me(): Promise<PublicUser> {
  const { data } = await apiClient.get<PublicUser>('/v1/users/me');
  return data;
}

export type RegistrationStatusValue = 'approved' | 'pending' | 'banned' | 'not_found';

// Looked up by the unguessable `registrationTrackingToken` returned from
// `register`, never by the account's own (guessable) user code — see
// server auth::registration_status.
export async function registrationStatus(trackingToken: string): Promise<RegistrationStatusValue> {
  const { data } = await apiClient.get<{ status: RegistrationStatusValue }>(
    `/v1/auth/registration-status/${encodeURIComponent(trackingToken)}`,
  );
  return data.status;
}
