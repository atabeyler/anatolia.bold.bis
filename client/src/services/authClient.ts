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

export async function register(payload: RegisterPayload): Promise<void> {
  await apiClient.post('/v1/auth/register', payload);
}

export async function refresh(): Promise<LoginResponse> {
  const { data } = await apiClient.post<LoginResponse>('/v1/auth/refresh');
  return data;
}

export async function logout(): Promise<void> {
  await apiClient.post('/v1/auth/logout');
}

export async function forgotPassword(identifier: string): Promise<void> {
  await apiClient.post('/v1/auth/forgot-password', { identifier });
}

export async function me(): Promise<PublicUser> {
  const { data } = await apiClient.get<PublicUser>('/v1/users/me');
  return data;
}

export type PendingStatusValue = 'approved' | 'pending' | 'banned' | 'not_found';

export async function pendingStatus(userCode: string): Promise<PendingStatusValue> {
  const { data } = await apiClient.get<{ status: PendingStatusValue }>(
    `/v1/auth/pending-status/${encodeURIComponent(userCode)}`,
  );
  return data.status;
}
