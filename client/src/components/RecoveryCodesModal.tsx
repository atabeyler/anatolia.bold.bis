import { useTranslation } from 'react-i18next';

interface RecoveryCodesModalProps {
  codes: string[];
  onAcknowledge: () => void;
}

// Shown exactly once, immediately after TOTP MFA enrollment completes —
// these codes are never retrievable again (only their hashes are stored
// server-side, see server/src/db/mfa.rs). Deliberately does not reuse the
// dismissible `Overlay` component: there is no backdrop-click or close
// button, only the explicit acknowledgement button, so a stray click can't
// lose the only chance to see these codes.
export function RecoveryCodesModal({ codes, onAcknowledge }: RecoveryCodesModalProps) {
  const { t } = useTranslation();
  return (
    <div className="overlay-backdrop">
      <div className="overlay-panel" role="dialog" aria-modal="true">
        <div className="overlay-header">
          <span className="overlay-header__title">{t('auth.mfa.recoveryCodesTitle')}</span>
        </div>
        <div className="overlay-body">
          <p>{t('auth.mfa.recoveryCodesIntro')}</p>
          <ul className="mfa-recovery-codes">
            {codes.map((code) => (
              <li key={code}>{code}</li>
            ))}
          </ul>
          <p className="mfa-recovery-codes__warning">{t('auth.mfa.recoveryCodesWarning')}</p>
          <button type="button" className="auth-submit" onClick={onAcknowledge}>
            {t('auth.mfa.recoveryCodesAcknowledge')}
          </button>
        </div>
      </div>
    </div>
  );
}
