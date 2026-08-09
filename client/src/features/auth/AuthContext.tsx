import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

import { setAccessToken } from '../../services/apiClient';
import * as authClient from '../../services/authClient';
import type { PublicUser, RegisterPayload } from '../../services/authClient';

const REMEMBERED_USER_CODE_KEY = 'anatolia_remembered_user_code';

interface AuthContextValue {
  user: PublicUser | null;
  status: 'loading' | 'signed-out' | 'signed-in';
  rememberedUserCode: string;
  login: (userCode: string, password: string, rememberMe: boolean) => Promise<void>;
  register: (payload: RegisterPayload) => Promise<string>;
  logout: () => Promise<void>;
  logoutAll: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<PublicUser | null>(null);
  const [status, setStatus] = useState<'loading' | 'signed-out' | 'signed-in'>('loading');
  const [rememberedUserCode, setRememberedUserCode] = useState(
    () => localStorage.getItem(REMEMBERED_USER_CODE_KEY) ?? '',
  );

  useEffect(() => {
    // A refresh cookie from a previous visit, if any, silently restores
    // the session on load — no separate "keep me signed in" toggle needed
    // beyond remembering the user code for convenience (see login below).
    authClient
      .refresh()
      .then(({ accessToken, user: refreshedUser }) => {
        setAccessToken(accessToken);
        setUser(refreshedUser);
        setStatus('signed-in');
      })
      .catch(() => {
        setAccessToken(null);
        setStatus('signed-out');
      });
  }, []);

  const login = useCallback(async (userCode: string, password: string, rememberMe: boolean) => {
    const { accessToken, user: loggedInUser } = await authClient.login(userCode, password);
    setAccessToken(accessToken);
    setUser(loggedInUser);
    setStatus('signed-in');
    if (rememberMe) {
      localStorage.setItem(REMEMBERED_USER_CODE_KEY, loggedInUser.userCode);
      setRememberedUserCode(loggedInUser.userCode);
    } else {
      localStorage.removeItem(REMEMBERED_USER_CODE_KEY);
      setRememberedUserCode('');
    }
  }, []);

  const register = useCallback(async (payload: RegisterPayload) => authClient.register(payload), []);

  const logout = useCallback(async () => {
    await authClient.logout().catch(() => {});
    setAccessToken(null);
    setUser(null);
    setStatus('signed-out');
  }, []);

  const logoutAll = useCallback(async () => {
    await authClient.logoutAll().catch(() => {});
    setAccessToken(null);
    setUser(null);
    setStatus('signed-out');
  }, []);

  const value = useMemo(
    () => ({ user, status, rememberedUserCode, login, register, logout, logoutAll }),
    [user, status, rememberedUserCode, login, register, logout, logoutAll],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
