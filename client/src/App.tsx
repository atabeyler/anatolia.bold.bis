import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { MenuOverlay } from './components/MenuOverlay';
import { SettingsOverlay } from './components/SettingsOverlay';
import { useAuth } from './features/auth/AuthContext';
import { useHealthCheck } from './hooks/useHealthCheck';
import { DashboardPage } from './pages/DashboardPage';
import { LoginPage } from './pages/LoginPage';

function App() {
  const { t, i18n } = useTranslation();
  const { user, status, logout } = useAuth();
  const health = useHealthCheck();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const brand = i18n.resolvedLanguage === 'tr' ? 'ANATOLİA-BİS' : 'ANATOLIA-BIS';

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <h1>{brand}</h1>
          <p className="app-header__tagline">{t('app.tagline')}</p>
          <p className={`app-header__status ${health.isSuccess ? 'app-header__status--online' : health.isError ? 'app-header__status--offline' : ''}`}>
            <span className="app-header__status-dot" aria-hidden="true" />
            {health.isSuccess ? t('status.online') : health.isError ? t('status.offline') : t('status.checking')}
          </p>
        </div>
        <div className="app-header__controls">
          {user && (
            <div className="app-header__session">
              <span>{t('auth.welcomeBack', { name: `${user.firstName} ${user.lastName}` })}</span>
              <button type="button" onClick={() => void logout()}>
                {t('auth.logout')}
              </button>
            </div>
          )}
          <div className="app-header__nav">
            <button type="button" className="app-header__nav-button" onClick={() => setSettingsOpen(true)}>
              ⚙ {t('settings.openLabel')}
            </button>
            <button type="button" className="app-header__nav-button" onClick={() => setMenuOpen(true)}>
              ☰ {t('menu.openLabel')}
            </button>
          </div>
        </div>
      </header>

      {status === 'loading' ? null : status === 'signed-in' ? <DashboardPage /> : <LoginPage />}

      <footer className="app-footer">
        <p>{t('footer.legal')}</p>
      </footer>

      {settingsOpen && <SettingsOverlay onClose={() => setSettingsOpen(false)} />}
      {menuOpen && <MenuOverlay onClose={() => setMenuOpen(false)} />}
    </div>
  );
}

export default App;
