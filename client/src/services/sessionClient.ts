import { apiClient } from './apiClient';

export interface UserSession {
  id: string;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
  userAgent: string | null;
  ipAddress: string | null;
  isCurrent: boolean;
}

export async function listSessions(): Promise<UserSession[]> {
  const { data } = await apiClient.get<{ items: UserSession[] }>('/v1/users/me/sessions');
  return data.items;
}

export async function revokeSession(sessionId: string): Promise<void> {
  await apiClient.delete(`/v1/users/me/sessions/${sessionId}`);
}
