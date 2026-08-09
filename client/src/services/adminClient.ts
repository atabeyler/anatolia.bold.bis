import { apiClient } from './apiClient';

export interface AdminUser {
  id: string;
  userCode: string;
  firstName: string;
  lastName: string;
  nationalId: string | null;
  email: string | null;
  role: string;
  isApproved: boolean;
  isBanned: boolean;
  banReason: string | null;
}

export interface CreateUserPayload {
  userCode: string;
  password: string;
  nickname?: string;
  nationalId: string;
  email: string;
  isAdmin: boolean;
}

export interface UpdateUserPayload {
  nickname?: string;
  nationalId?: string;
  email?: string;
  password?: string;
}

export async function listUsers(): Promise<AdminUser[]> {
  const { data } = await apiClient.get<AdminUser[]>('/v1/admin/users');
  return data;
}

export async function createUser(payload: CreateUserPayload): Promise<AdminUser> {
  const { data } = await apiClient.post<{ user: AdminUser }>('/v1/admin/users', payload);
  return data.user;
}

export async function updateUser(id: string, payload: UpdateUserPayload): Promise<AdminUser> {
  const { data } = await apiClient.patch<{ user: AdminUser }>(`/v1/admin/users/${id}`, payload);
  return data.user;
}

export async function approveUser(id: string): Promise<void> {
  await apiClient.post(`/v1/admin/users/${id}/approve`);
}

export async function rejectUser(id: string): Promise<void> {
  await apiClient.post(`/v1/admin/users/${id}/reject`);
}

export async function banUser(id: string, reason?: string): Promise<void> {
  await apiClient.post(`/v1/admin/users/${id}/ban`, { reason });
}

export async function unbanUser(id: string): Promise<void> {
  await apiClient.post(`/v1/admin/users/${id}/unban`);
}

export async function deleteUser(id: string): Promise<void> {
  await apiClient.delete(`/v1/admin/users/${id}`);
}
