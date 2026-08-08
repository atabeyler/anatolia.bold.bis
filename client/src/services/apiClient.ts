import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10_000,
  // The refresh token travels as an HttpOnly cookie set by the backend;
  // it is never readable from JavaScript, so every request must opt in
  // to sending cookies for /auth/refresh to work.
  withCredentials: true,
});

let currentAccessToken: string | null = null;

export function setAccessToken(token: string | null): void {
  currentAccessToken = token;
}

apiClient.interceptors.request.use((config) => {
  if (currentAccessToken) {
    config.headers.set('Authorization', `Bearer ${currentAccessToken}`);
  }
  return config;
});

export interface ApiErrorBody {
  code: string;
  messageKey: string;
  requestId: string;
  details?: unknown;
}

export function apiErrorMessageKey(error: unknown, fallback = 'errors.internal'): string {
  if (axios.isAxiosError(error) && error.response?.data && typeof error.response.data === 'object') {
    const body = error.response.data as Partial<ApiErrorBody>;
    if (typeof body.messageKey === 'string') {
      return body.messageKey;
    }
  }
  return fallback;
}
