import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { Logo } from '../components/Logo';
import { brandMark } from '../lib/brand';
import { apiErrorMessageKey } from '../services/apiClient';
import * as authClient from '../services/authClient';

interface ResetPasswordPageProps {
  token: string;
  onDone: () => void;
}

/// Reached via the emailed reset link (`{APP_URL}/?resetToken=...`), never
/// through normal in-app navigation — see `App.tsx`'s `resetToken` query
/// param check, which renders this instead of the login screen regardless
/// of current auth state.
export function ResetPasswordPage({ token, onDone }: ResetPasswordPageProps) {
  const { t, i18n } = useTranslation();
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setErrorKey(null);
    if (newPassword !== confirmPassword) {
      setErrorKey('auth.resetPassword.mismatch');
      return;
    }
    setSubmitting(true);
    try {
      await authClient.resetPassword(token, newPassword);
      setSuccess(true);
    } catch (err) {
      setErrorKey(apiErrorMessageKey(err));
    } finally {
      setSubmitting(false);
    }
  };

  const brand = brandMark(i18n.resolvedLanguage);

  return (
    <div className="auth-shell">
      <Logo />
      <div className="auth-brand">
        <h1 className="auth-brand__title">{brand}</h1>
        <p className="auth-brand__tagline">{t('auth.resetPassword.title')}</p>
      </div>

      <div className="auth-divider" aria-hidden="true">
        <span />
        <span className="auth-divider__mark" />
        <span />
      </div>

      {success ? (
        <div className="auth-panel">
          <p className="auth-message auth-message--success">{t('auth.resetPassword.success')}</p>
          <button type="button" className="auth-submit" onClick={onDone}>
            {t('auth.backToLogin')}
          </button>
        </div>
      ) : (
        <form className="auth-panel" onSubmit={handleSubmit}>
          <label className="auth-field">
            <span>{t('auth.resetPassword.newPassword')}</span>
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} minLength={8} required />
            <small>{t('auth.passwordHint')}</small>
          </label>
          <label className="auth-field">
            <span>{t('auth.resetPassword.confirmPassword')}</span>
            <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} minLength={8} required />
          </label>

          {errorKey && <p className="auth-message auth-message--error">{t(errorKey)}</p>}

          <button type="submit" className="auth-submit" disabled={submitting}>
            {submitting ? t('auth.submitting') : t('auth.resetPassword.submit')}
          </button>
          <button type="button" className="auth-link-button" onClick={onDone}>
            {t('auth.backToLogin')}
          </button>
        </form>
      )}
    </div>
  );
}
