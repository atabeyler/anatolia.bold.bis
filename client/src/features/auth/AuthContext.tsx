import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';

import { setAccessToken } from '../../services/apiClient';
import { createAuthBroadcastChannel, isSignedOutMessage, postSignedOut } from '../../services/authBroadcast';
import * as authClient from '../../services/authClient';
import { isMfaChallenge, isMfaEnrollmentRequired } from '../../services/authClient';
import type { LoginOutcome, MfaEnrollmentStart, PublicUser, RegisterPayload } from '../../services/authClient';

const REMEMBERED_USER_CODE_KEY = 'anatolia_remembered_user_code';

// What the caller (LoginPage) must do next after `login()` resolves —
// either the session is already established, or an MFA step must be
// completed first (see server/src/mfa.rs for why no session is issued
// until then).
export type LoginStep =
  | { type: 'signedIn' }
  | { type: 'mfaChallenge'; mfaToken: string }
  | { type: 'mfaEnrollmentRequired'; mfaToken: string };

interface AuthContextValue {
  user: PublicUser | null;
  status: 'loading' | 'signed-out' | 'signed-in';
  rememberedUserCode: string;
  login: (userCode: string, password: string, rememberMe: boolean) => Promise<LoginStep>;
  completeMfaChallenge: (mfaToken: string, code: string, rememberMe: boolean) => Promise<void>;
  beginMfaEnrollmentChallenge: (mfaToken: string) => Promise<MfaEnrollmentStart>;
  completeMfaEnrollmentChallenge: (mfaToken: string, code: string, rememberMe: boolean) => Promise<void>;
  // Shown once, immediately after MFA enrollment completes — see the
  // `RecoveryCodesModal` rendered in App.tsx. Cleared by
  // `acknowledgeRecoveryCodes` once the operator confirms they were saved.
  pendingRecoveryCodes: string[] | null;
  acknowledgeRecoveryCodes: () => void;
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
  const [pendingRecoveryCodes, setPendingRecoveryCodes] = useState<string[] | null>(null);
  const broadcastRef = useRef<BroadcastChannel | null>(null);

  useEffect(() => {
    const channel = createAuthBroadcastChannel();
    broadcastRef.current = channel;
    if (!channel) {
      return;
    }
    const handleMessage = (event: MessageEvent) => {
      if (!isSignedOutMessage(event.data)) {
        return;
      }
      setAccessToken(null);
      setUser(null);
      setStatus('signed-out');
    };
    channel.addEventListener('message', handleMessage);
    return () => {
      channel.removeEventListener('message', handleMessage);
      channel.close();
      broadcastRef.current = null;
    };
  }, []);

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

  const applySession = useCallback((accessToken: string, sessionUser: PublicUser, rememberMe: boolean) => {
    setAccessToken(accessToken);
    setUser(sessionUser);
    setStatus('signed-in');
    if (rememberMe) {
      localStorage.setItem(REMEMBERED_USER_CODE_KEY, sessionUser.userCode);
      setRememberedUserCode(sessionUser.userCode);
    } else {
      localStorage.removeItem(REMEMBERED_USER_CODE_KEY);
      setRememberedUserCode('');
    }
  }, []);

  const login = useCallback(
    async (userCode: string, password: string, rememberMe: boolean): Promise<LoginStep> => {
      const outcome: LoginOutcome = await authClient.login(userCode, password);
      if (isMfaChallenge(outcome)) {
        return { type: 'mfaChallenge', mfaToken: outcome.mfaToken };
      }
      if (isMfaEnrollmentRequired(outcome)) {
        return { type: 'mfaEnrollmentRequired', mfaToken: outcome.mfaToken };
      }
      applySession(outcome.accessToken, outcome.user, rememberMe);
      return { type: 'signedIn' };
    },
    [applySession],
  );

  const completeMfaChallenge = useCallback(
    async (mfaToken: string, code: string, rememberMe: boolean) => {
      const { accessToken, user: sessionUser } = await authClient.mfaChallengeVerify(mfaToken, code);
      applySession(accessToken, sessionUser, rememberMe);
    },
    [applySession],
  );

  const beginMfaEnrollmentChallenge = useCallback(
    async (mfaToken: string) => authClient.mfaChallengeEnroll(mfaToken),
    [],
  );

  const completeMfaEnrollmentChallenge = useCallback(
    async (mfaToken: string, code: string, rememberMe: boolean) => {
      const { accessToken, user: sessionUser, recoveryCodes } = await authClient.mfaChallengeEnrollConfirm(
        mfaToken,
        code,
      );
      setPendingRecoveryCodes(recoveryCodes ?? []);
      applySession(accessToken, sessionUser, rememberMe);
    },
    [applySession],
  );

  const acknowledgeRecoveryCodes = useCallback(() => setPendingRecoveryCodes(null), []);

  const register = useCallback(async (payload: RegisterPayload) => authClient.register(payload), []);

  const logout = useCallback(async () => {
    await authClient.logout().catch(() => {});
    setAccessToken(null);
    setUser(null);
    setStatus('signed-out');
    postSignedOut(broadcastRef.current);
  }, []);

  const logoutAll = useCallback(async () => {
    await authClient.logoutAll().catch(() => {});
    setAccessToken(null);
    setUser(null);
    setStatus('signed-out');
    postSignedOut(broadcastRef.current);
  }, []);

  const value = useMemo(
    () => ({
      user,
      status,
      rememberedUserCode,
      login,
      completeMfaChallenge,
      beginMfaEnrollmentChallenge,
      completeMfaEnrollmentChallenge,
      pendingRecoveryCodes,
      acknowledgeRecoveryCodes,
      register,
      logout,
      logoutAll,
    }),
    [
      user,
      status,
      rememberedUserCode,
      login,
      completeMfaChallenge,
      beginMfaEnrollmentChallenge,
      completeMfaEnrollmentChallenge,
      pendingRecoveryCodes,
      acknowledgeRecoveryCodes,
      register,
      logout,
      logoutAll,
    ],
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
