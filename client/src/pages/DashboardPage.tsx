import { useTranslation } from 'react-i18next';

import { useHealthCheck } from '../hooks/useHealthCheck';

export function DashboardPage() {
  const { t } = useTranslation();
  const health = useHealthCheck();

  return (
    <main className="dashboard">
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
