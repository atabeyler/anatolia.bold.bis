import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { MenuOverlay } from './components/MenuOverlay';
import { SettingsOverlay } from './components/SettingsOverlay';
import { useAuth } from './features/auth/AuthContext';
import { DashboardPage } from './pages/DashboardPage';
import { LoginPage } from './pages/LoginPage';

function App() {
  const { t } = useTranslation();
  const { user, status, logout } = useAuth();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <h1>{t('app.title')}</h1>
          <p className="app-header__tagline">{t('app.tagline')}</p>
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
