import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { MenuOverlay } from './components/MenuOverlay';
import { SettingsOverlay } from './components/SettingsOverlay';
import { useAuth } from './features/auth/AuthContext';
import { AdminPage } from './pages/AdminPage';
import { DashboardPage } from './pages/DashboardPage';
import { LoginPage } from './pages/LoginPage';

const ADMIN_ROLES = ['SYSTEM_ADMIN', 'SECURITY_ADMIN'];

type View = 'dashboard' | 'admin';

function App() {
  const { t } = useTranslation();
  const { status, user } = useAuth();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [view, setView] = useState<View | null>(null);
  const isAdmin = !!user && ADMIN_ROLES.includes(user.role);

  useEffect(() => {
    if (status === 'signed-in' && view === null) {
      // Admins land straight on the management panel — no intermediate
      // dashboard click required — while everyone else lands on the
      // dashboard as before.
      setView(isAdmin ? 'admin' : 'dashboard');
    }
    if (status !== 'signed-in' && view !== null) {
      setView(null);
    }
  }, [status, isAdmin, view]);

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
        {status === 'loading' ? null : status === 'signed-in' ? (
          view === 'admin' ? (
            <AdminPage onGoHome={() => setView('dashboard')} />
          ) : (
            <DashboardPage onOpenAdmin={isAdmin ? () => setView('admin') : undefined} />
          )
        ) : (
          <LoginPage />
        )}
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
