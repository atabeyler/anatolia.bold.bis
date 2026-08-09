import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { Logo } from '../components/Logo';
import { useAuth } from '../features/auth/AuthContext';
import { formatLatitude, formatLongitude, useGeolocation } from '../hooks/useGeolocation';
import { brandMark } from '../lib/brand';
import { playChimeIfEnabled } from '../lib/sound';
import { apiErrorMessageKey } from '../services/apiClient';
import * as authClient from '../services/authClient';

type Mode = 'login' | 'register' | 'forgot';

const USER_CODE_PATTERN = /^[A-Z0-9]{4,20}$/;
const NATIONAL_ID_PATTERN = /^[0-9]{11}$/;

export function LoginPage() {
  const { t, i18n } = useTranslation();
  const { login, register, rememberedUserCode } = useAuth();
  const geolocation = useGeolocation();

  const [mode, setMode] = useState<Mode>('login');
  const [userCode, setUserCode] = useState(rememberedUserCode);
  const [password, setPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [nationalId, setNationalId] = useState('');
  const [email, setEmail] = useState('');
  const [rememberMe, setRememberMe] = useState(Boolean(rememberedUserCode));
  const [submitting, setSubmitting] = useState(false);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [pendingCode, setPendingCode] = useState<string | null>(null);
  const [pendingTrackingToken, setPendingTrackingToken] = useState<string | null>(null);
  const [approvedMessage, setApprovedMessage] = useState(false);
  const [forgotIdentifier, setForgotIdentifier] = useState('');
  const [forgotSuccess, setForgotSuccess] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!pendingTrackingToken) {
      return;
    }
    pollRef.current = setInterval(async () => {
      try {
        const status = await authClient.registrationStatus(pendingTrackingToken);
        if (status === 'approved') {
          if (pollRef.current) clearInterval(pollRef.current);
          setPendingTrackingToken(null);
          setApprovedMessage(true);
          setMode('login');
          setUserCode(pendingCode ?? '');
          setPendingCode(null);
        }
      } catch {
        // Transient network errors just wait for the next poll tick.
      }
    }, 10_000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [pendingTrackingToken, pendingCode]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setErrorKey(null);
    setSubmitting(true);
    try {
      if (mode === 'login') {
        await login(userCode.trim().toUpperCase(), password, rememberMe);
        playChimeIfEnabled();
      } else if (mode === 'register') {
        const code = userCode.trim().toUpperCase();
        const trackingToken = await register({ firstName, lastName, nationalId, email, password, userCode: code });
        setPendingCode(code);
        setPendingTrackingToken(trackingToken);
        setMode('login');
        setPassword('');
        playChimeIfEnabled();
      } else {
        await authClient.forgotPassword(forgotIdentifier.trim());
        setForgotSuccess(true);
      }
    } catch (err) {
      setErrorKey(apiErrorMessageKey(err));
    } finally {
      setSubmitting(false);
    }
  }

  const locationLine =
    geolocation.status === 'granted' && geolocation.coords
      ? `LAT: ${formatLatitude(geolocation.coords.latitude)} · LON: ${formatLongitude(geolocation.coords.longitude)}`
      : geolocation.status === 'denied'
        ? t('status.locationDenied')
        : geolocation.status === 'unsupported'
          ? t('status.locationUnsupported')
          : t('status.locationRequesting');

  const brand = brandMark(i18n.resolvedLanguage);

  return (
    <div className="auth-shell">
      <div className="auth-telemetry">
        <div>
          SYS: {brand} v{__APP_VERSION__}
        </div>
        <div>{locationLine}</div>
      </div>

      <Logo />

      <div className="auth-brand">
        <h1 className="auth-brand__title">{brand}</h1>
        <p className="auth-brand__tagline">{t('app.tagline')}</p>
      </div>

      <div className="auth-divider" aria-hidden="true">
        <span />
        <span className="auth-divider__mark" />
        <span />
      </div>

      <form className="auth-panel" onSubmit={handleSubmit}>
        {mode !== 'forgot' && (
          <div className="auth-mode-toggle">
            <button
              type="button"
              className={mode === 'login' ? 'active' : ''}
              onClick={() => {
                setMode('login');
                setErrorKey(null);
              }}
            >
              {t('auth.signIn')}
            </button>
            <button
              type="button"
              className={mode === 'register' ? 'active' : ''}
              onClick={() => {
                setMode('register');
                setErrorKey(null);
              }}
            >
              {t('auth.signUp')}
            </button>
          </div>
        )}

        {mode === 'register' && (
          <div className="auth-field-row">
            <label className="auth-field">
              <span>{t('auth.firstName')}</span>
              <input value={firstName} onChange={(e) => setFirstName(e.target.value)} required />
            </label>
            <label className="auth-field">
              <span>{t('auth.lastName')}</span>
              <input value={lastName} onChange={(e) => setLastName(e.target.value)} required />
            </label>
          </div>
        )}

        {mode !== 'forgot' && (
          <label className="auth-field">
            <span>{t('auth.userCode')}</span>
            <input
              value={userCode}
              onChange={(e) => setUserCode(e.target.value.toUpperCase())}
              maxLength={20}
              required
              pattern={mode === 'register' ? USER_CODE_PATTERN.source : undefined}
            />
            {mode === 'register' && <small>{t('auth.userCodeHint')}</small>}
          </label>
        )}

        {mode === 'register' && (
          <label className="auth-field">
            <span>{t('auth.nationalId')}</span>
            <input
              value={nationalId}
              onChange={(e) => setNationalId(e.target.value.replace(/[^0-9]/g, ''))}
              maxLength={11}
              pattern={NATIONAL_ID_PATTERN.source}
              required
            />
          </label>
        )}

        {mode === 'register' && (
          <label className="auth-field">
            <span>{t('auth.email')}</span>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
          </label>
        )}

        {mode === 'forgot' && (
          <label className="auth-field">
            <span>{t('auth.forgotPasswordIdentifier')}</span>
            <input value={forgotIdentifier} onChange={(e) => setForgotIdentifier(e.target.value)} required />
          </label>
        )}

        {mode !== 'forgot' && (
          <label className="auth-field">
            <span>{t('auth.password')}</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            {mode === 'register' && <small>{t('auth.passwordHint')}</small>}
          </label>
        )}

        {mode === 'login' && (
          <>
            <label className="auth-remember">
              <input type="checkbox" checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} />
              <span>{t('auth.rememberMe')}</span>
            </label>
            <button
              type="button"
              className="auth-link-button"
              onClick={() => {
                setMode('forgot');
                setErrorKey(null);
                setForgotSuccess(false);
              }}
            >
              {t('auth.forgotPassword')}
            </button>
          </>
        )}

        {mode === 'forgot' && (
          <button
            type="button"
            className="auth-link-button"
            onClick={() => {
              setMode('login');
              setErrorKey(null);
              setForgotSuccess(false);
            }}
          >
            {t('auth.backToLogin')}
          </button>
        )}

        {errorKey && <p className="auth-message auth-message--error">{t(errorKey)}</p>}
        {approvedMessage && <p className="auth-message auth-message--success">{t('auth.accountApproved')}</p>}
        {pendingCode && (
          <p className="auth-message auth-message--pending">
            {t('auth.registrationPendingMessage', { code: pendingCode })}
          </p>
        )}
        {forgotSuccess && <p className="auth-message auth-message--success">{t('auth.forgotPasswordSuccess')}</p>}

        {mode !== 'forgot' && (
          <button type="submit" className="auth-submit" disabled={submitting}>
            {submitting ? t('auth.submitting') : mode === 'login' ? t('auth.submitLogin') : t('auth.submitRegister')}
          </button>
        )}
        {mode === 'forgot' && !forgotSuccess && (
          <button type="submit" className="auth-submit" disabled={submitting}>
            {submitting ? t('auth.submitting') : t('auth.forgotPasswordSubmit')}
          </button>
        )}
      </form>
    </div>
  );
}
