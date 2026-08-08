import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { MenuOverlay } from './components/MenuOverlay';
import { SettingsOverlay } from './components/SettingsOverlay';
import { useAuth } from './features/auth/AuthContext';
import { DashboardPage } from './pages/DashboardPage';
import { LoginPage } from './pages/LoginPage';

function App() {
  const { t } = useTranslation();
  const { status } = useAuth();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <div className="app-shell">
      <div className="app-nav-fixed">
        <button type="button" className="app-header__nav-button" onClick={() => setSettingsOpen(true)}>
          ⚙ {t('settings.openLabel')}
        </button>
        <button type="button" className="app-header__nav-button" onClick={() => setMenuOpen(true)}>
          ☰ {t('menu.openLabel')}
        </button>
      </div>

      <div className="app-main">
        {status === 'loading' ? null : status === 'signed-in' ? <DashboardPage /> : <LoginPage />}
      </div>

      <footer className="app-footer">
        <span>{t('footer.legalCode')}</span>
        <span className="app-footer__separator">·</span>
        <span>{t('footer.legalCompany')}</span>
        <span className="app-footer__separator">·</span>
        <span>{t('footer.legalRights')}</span>
      </footer>

      {settingsOpen && <SettingsOverlay onClose={() => setSettingsOpen(false)} />}
      {menuOpen && <MenuOverlay onClose={() => setMenuOpen(false)} />}
    </div>
  );
}

export default App;
