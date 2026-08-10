import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import * as systemClient from '../services/systemClient';
import type { AuditIntegrityReport, BiometricThreshold, HealthReady } from '../services/systemClient';
import { apiErrorMessageKey } from '../services/apiClient';

export function SystemPanel() {
  const { t } = useTranslation();
  const [health, setHealth] = useState<HealthReady | null>(null);
  const [healthError, setHealthError] = useState(false);

  const [thresholds, setThresholds] = useState<BiometricThreshold[] | null>(null);
  const [thresholdsError, setThresholdsError] = useState(false);

  const [integrityReport, setIntegrityReport] = useState<AuditIntegrityReport | null>(null);
  const [integrityMessage, setIntegrityMessage] = useState<string | null>(null);
  const [checkingIntegrity, setCheckingIntegrity] = useState(false);

  useEffect(() => {
    systemClient
      .getHealthReady()
      .then(setHealth)
      .catch(() => setHealthError(true));
    systemClient
      .listBiometricThresholds()
      .then(setThresholds)
      .catch(() => setThresholdsError(true));
  }, []);

  const handleCheckIntegrity = async () => {
    setCheckingIntegrity(true);
    setIntegrityMessage(null);
    setIntegrityReport(null);
    try {
      const report = await systemClient.verifyAuditIntegrity();
      setIntegrityReport(report);
    } catch (error) {
      setIntegrityMessage(t(apiErrorMessageKey(error, 'errors.internal')) ?? '');
    } finally {
      setCheckingIntegrity(false);
    }
  };

  return (
    <>
      <section className="admin-panel">
        <h2 className="admin-panel__heading">{t('admin.system.healthHeading')}</h2>
        {health === null && !healthError && <p className="status-card__line">{t('admin.loading')}</p>}
        {healthError && (
          <p className="status-card__line status-card__line--offline">{t('admin.loadError')}</p>
        )}
        {health && (
          <ul className="admin-key-value-list">
            <li>
              <span>{t('admin.system.status')}</span>
              <span>{health.status}</span>
            </li>
            <li>
              <span>{t('admin.system.version')}</span>
              <span>{health.version}</span>
            </li>
            <li>
              <span>{t('admin.system.biometricProvider')}</span>
              <span>{health.biometricProvider}</span>
            </li>
            <li>
              <span>{t('admin.system.biometricSearch')}</span>
              <span>{health.biometricSearch}</span>
            </li>
          </ul>
        )}
      </section>

      <section className="admin-panel">
        <h2 className="admin-panel__heading">{t('admin.system.thresholdsHeading')}</h2>
        {thresholds === null && !thresholdsError && <p className="status-card__line">{t('admin.loading')}</p>}
        {thresholdsError && (
          <p className="status-card__line status-card__line--offline">{t('admin.loadError')}</p>
        )}
        {thresholds !== null && thresholds.length === 0 && (
          <p className="status-card__line">{t('admin.system.thresholdsEmpty')}</p>
        )}
        {thresholds && thresholds.length > 0 && (
          <ul className="admin-key-value-list">
            {thresholds.map((threshold) => (
              <li key={threshold.id}>
                <span>
                  {threshold.modelName} ({threshold.modelVersion})
                </span>
                <span>
                  {t('admin.system.thresholdSummary', {
                    threshold: threshold.threshold.toFixed(4),
                    eer: threshold.equalErrorRate.toFixed(4),
                    pairCount: threshold.pairCount,
                  })}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="admin-panel">
        <h2 className="admin-panel__heading">{t('admin.system.integrityHeading')}</h2>
        <p className="admin-hint">{t('admin.system.integrityHint')}</p>
        <button
          type="button"
          className="admin-submit"
          disabled={checkingIntegrity}
          onClick={handleCheckIntegrity}
        >
          {t('admin.system.integrityCheckSubmit')}
        </button>
        {integrityMessage && <p className="auth-message auth-message--error">{integrityMessage}</p>}
        {integrityReport && (
          <p
            className={`auth-message ${integrityReport.intact ? 'auth-message--success' : 'auth-message--error'}`}
          >
            {integrityReport.intact
              ? t('admin.system.integrityIntact', {
                  eventsChecked: integrityReport.eventsChecked,
                })
              : t('admin.system.integrityBroken', {
                  eventsChecked: integrityReport.eventsChecked,
                  breaks: integrityReport.breaks.length,
                })}
          </p>
        )}
      </section>
    </>
  );
}
