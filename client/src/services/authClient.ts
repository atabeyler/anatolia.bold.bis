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
}

export interface RegisterPayload {
  firstName: string;
  lastName: string;
  nationalId: string;
  email: string;
  password: string;
  userCode: string;
}

export async function login(userCode: string, password: string): Promise<LoginResponse> {
  const { data } = await apiClient.post<LoginResponse>('/v1/auth/login', { userCode, password });
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
