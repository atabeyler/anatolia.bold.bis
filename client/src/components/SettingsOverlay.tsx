import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { useAuth } from '../features/auth/AuthContext';
import { LANGUAGE_NAMES, SUPPORTED_LANGUAGES } from '../i18n/config';
import { apiErrorMessageKey } from '../services/apiClient';
import * as sessionClient from '../services/sessionClient';
import type { UserSession } from '../services/sessionClient';
import { isSoundEnabled, playChime, setSoundEnabled } from '../lib/sound';
import { applyTheme, getStoredTheme, type Theme } from '../lib/theme';
import { Overlay } from './Overlay';

type Tab = 'language' | 'sound' | 'appearance' | 'sessions' | 'about';

const TABS: Array<{ id: Tab; labelKey: string }> = [
  { id: 'language', labelKey: 'settings.tabs.language' },
  { id: 'sound', labelKey: 'settings.tabs.sound' },
  { id: 'appearance', labelKey: 'settings.tabs.appearance' },
  { id: 'sessions', labelKey: 'settings.tabs.sessions' },
  { id: 'about', labelKey: 'settings.tabs.about' },
];

interface SettingsOverlayProps {
  onClose: () => void;
  onBack?: () => void;
}

export function SettingsOverlay({ onClose, onBack }: SettingsOverlayProps) {
  const { t, i18n } = useTranslation();
  const { status: authStatus } = useAuth();
  const [tab, setTab] = useState<Tab>('language');
  const [soundEnabled, setSoundEnabledState] = useState(isSoundEnabled());
  const [theme, setTheme] = useState<Theme>(getStoredTheme());

  const [sessions, setSessions] = useState<UserSession[] | null>(null);
  const [sessionsError, setSessionsError] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [sessionMessage, setSessionMessage] = useState<string | null>(null);

  const loadSessions = () => {
    setSessionsError(false);
    sessionClient
      .listSessions()
      .then(setSessions)
      .catch(() => setSessionsError(true));
  };

  useEffect(() => {
    if (tab === 'sessions' && authStatus === 'signed-in') {
      loadSessions();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, authStatus]);

  const handleRevoke = async (sessionId: string) => {
    setRevokingId(sessionId);
    setSessionMessage(null);
    try {
      await sessionClient.revokeSession(sessionId);
      loadSessions();
    } catch (error) {
      setSessionMessage(t(apiErrorMessageKey(error, 'errors.internal')) ?? '');
    } finally {
      setRevokingId(null);
    }
  };

  function toggleSound() {
    const next = !soundEnabled;
    setSoundEnabled(next);
    setSoundEnabledState(next);
    if (next) {
      playChime();
    }
  }

  function chooseTheme(next: Theme) {
    applyTheme(next);
    setTheme(next);
  }

  return (
    <Overlay title={t('settings.title')} onClose={onClose} onBack={onBack}>
      <div className="overlay-tabs">
        {TABS.map((item) => (
          <button
            key={item.id}
            type="button"
            className={item.id === tab ? 'overlay-tabs__tab overlay-tabs__tab--active' : 'overlay-tabs__tab'}
            onClick={() => setTab(item.id)}
          >
            {t(item.labelKey)}
          </button>
        ))}
      </div>

      {tab === 'language' && (
        <ul className="overlay-list">
          {SUPPORTED_LANGUAGES.map((language) => (
            <li key={language}>
              <button type="button" className="overlay-list__item" onClick={() => void i18n.changeLanguage(language)}>
                <span>{LANGUAGE_NAMES[language]}</span>
                {i18n.resolvedLanguage === language && <span aria-hidden="true">✓</span>}
              </button>
            </li>
          ))}
        </ul>
      )}

      {tab === 'sound' && (
        <div className="overlay-setting-row">
          <label className="overlay-toggle">
            <input type="checkbox" checked={soundEnabled} onChange={toggleSound} />
            <span>{t('settings.sound.enable')}</span>
          </label>
          <button type="button" className="overlay-secondary-button" onClick={() => playChime()}>
            {t('settings.sound.test')}
          </button>
        </div>
      )}

      {tab === 'appearance' && (
        <div className="overlay-setting-row">
          <button
            type="button"
            className={theme === 'dark' ? 'overlay-secondary-button overlay-secondary-button--active' : 'overlay-secondary-button'}
            onClick={() => chooseTheme('dark')}
          >
            {t('settings.appearance.dark')}
          </button>
          <button
            type="button"
            className={theme === 'light' ? 'overlay-secondary-button overlay-secondary-button--active' : 'overlay-secondary-button'}
            onClick={() => chooseTheme('light')}
          >
            {t('settings.appearance.light')}
          </button>
        </div>
      )}

      {tab === 'sessions' && (
        <div className="overlay-content">
          {authStatus !== 'signed-in' && <p className="admin-hint">{t('settings.sessions.signedOutHint')}</p>}
          {authStatus === 'signed-in' && (
            <>
              {sessions === null && !sessionsError && <p className="status-card__line">{t('admin.loading')}</p>}
              {sessionsError && (
                <p className="status-card__line status-card__line--offline">{t('admin.loadError')}</p>
              )}
              {sessionMessage && <p className="auth-message auth-message--error">{sessionMessage}</p>}
              {sessions !== null && sessions.length === 0 && (
                <p className="status-card__line">{t('settings.sessions.empty')}</p>
              )}
              <ul className="overlay-list">
                {sessions?.map((session) => (
                  <li key={session.id} className="overlay-list__item overlay-list__item--session">
                    <div>
                      <div>
                        {session.userAgent ?? t('settings.sessions.unknownDevice')}
                        {session.isCurrent && (
                          <span className="admin-badge admin-badge--admin">
                            {t('settings.sessions.currentBadge')}
                          </span>
                        )}
                      </div>
                      <div className="admin-user-card__note">
                        {t('settings.sessions.lastUsed', { date: new Date(session.lastUsedAt).toLocaleString(i18n.resolvedLanguage) })}
                        {session.ipAddress ? ` · ${session.ipAddress}` : ''}
                      </div>
                    </div>
                    {!session.isCurrent && (
                      <button
                        type="button"
                        className="overlay-secondary-button"
                        disabled={revokingId === session.id}
                        onClick={() => void handleRevoke(session.id)}
                      >
                        {t('settings.sessions.signOut')}
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}

      {tab === 'about' && (
        <div className="overlay-content">
          {t('menu.aboutContent')
            .split('\n')
            .map((line, index) => (
              <p key={index} className={line === line.toUpperCase() && line.trim().length > 2 ? 'overlay-content__heading' : undefined}>
                {line || ' '}
              </p>
            ))}
        </div>
      )}
    </Overlay>
  );
}
