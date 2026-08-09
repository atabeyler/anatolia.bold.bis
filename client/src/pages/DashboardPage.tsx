import { useTranslation } from 'react-i18next';

import { useAuth } from '../features/auth/AuthContext';
import { useHealthCheck } from '../hooks/useHealthCheck';
import { brandMark } from '../lib/brand';

const ADMIN_ROLES = ['SYSTEM_ADMIN', 'SECURITY_ADMIN'];

interface DashboardPageProps {
  onOpenAdmin?: () => void;
}

export function DashboardPage({ onOpenAdmin }: DashboardPageProps) {
  const { t, i18n } = useTranslation();
  const { user, logout } = useAuth();
  const health = useHealthCheck();
  const isAdmin = !!user && ADMIN_ROLES.includes(user.role);

  return (
    <main className="dashboard">
      <header className="dashboard__header">
        <h1 className="dashboard__brand">{brandMark(i18n.resolvedLanguage)}</h1>
        {user && (
          <div className="app-header__session">
            <span>{t('auth.welcomeBack', { name: `${user.firstName} ${user.lastName}` })}</span>
            {isAdmin && onOpenAdmin && (
              <button type="button" onClick={onOpenAdmin}>
                {t('admin.openLabel')}
              </button>
            )}
            <button type="button" onClick={() => void logout()}>
              {t('auth.logout')}
            </button>
          </div>
        )}
      </header>

      <section className="status-card">
        {health.isPending && <p className="status-card__line">{t('status.checking')}</p>}
        {health.isError && (
          <p className="status-card__line status-card__line--offline">{t('status.offline')}</p>
        )}
        {health.data && (
          <>
            <p className="status-card__line status-card__line--online">{t('status.online')}</p>
            <p className="status-card__line status-card__mono">
              {t('status.version')}: {health.data.version}
            </p>
          </>
        )}
      </section>
    </main>
  );
}
