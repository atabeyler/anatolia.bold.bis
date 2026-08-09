import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Logo } from './components/Logo';
import { MenuOverlay } from './components/MenuOverlay';
import { useAuth } from './features/auth/AuthContext';
import { brandMark } from './lib/brand';
import { AdminPage } from './pages/AdminPage';
import { DashboardPage } from './pages/DashboardPage';
import { LoginPage } from './pages/LoginPage';

const ADMIN_ROLES = ['SYSTEM_ADMIN', 'SECURITY_ADMIN'];

type View = 'dashboard' | 'admin';

function App() {
  const { t, i18n } = useTranslation();
  const { status, user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [view, setView] = useState<View | null>(null);
  const isAdmin = !!user && ADMIN_ROLES.includes(user.role);
  const signedIn = status === 'signed-in';

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
      {signedIn ? (
        // Logo, brand, contextual subtitle, and session actions stay
        // pinned in one bar across every signed-in screen, rather than
        // scrolling away with page content (see .app-topbar).
        <header className="app-topbar">
          <div className="app-topbar__brand">
            <Logo compact />
            <div>
              <div className="app-topbar__title">{brandMark(i18n.resolvedLanguage)}</div>
              <div className="app-topbar__subtitle">
                {view === 'admin' ? t('admin.panelTitle') : t('search.subtitle')}
              </div>
            </div>
          </div>
          <div className="app-topbar__actions">
            {view === 'admin' ? (
              <button type="button" className="app-header__nav-button" onClick={() => setView('dashboard')}>
                {t('admin.goHome')}
              </button>
            ) : (
              user && (
                <div className="app-header__session">
                  <span>{t('auth.welcomeBack', { name: `${user.firstName} ${user.lastName}` })}</span>
                  {isAdmin && (
                    <button type="button" onClick={() => setView('admin')}>
                      {t('admin.openLabel')}
                    </button>
                  )}
                  <button type="button" onClick={() => void logout()}>
                    {t('auth.logout')}
                  </button>
                </div>
              )
            )}
            <button type="button" className="app-header__nav-button" onClick={() => setMenuOpen(true)}>
              ☰ {t('menu.openLabel')}
            </button>
          </div>
        </header>
      ) : (
        <div className="app-nav-fixed">
          <button type="button" className="app-header__nav-button" onClick={() => setMenuOpen(true)}>
            ☰ {t('menu.openLabel')}
          </button>
        </div>
      )}

      <div className={signedIn ? 'app-main app-main--with-topbar' : 'app-main'}>
        {status === 'loading' ? null : signedIn ? (
          view === 'admin' ? <AdminPage /> : <DashboardPage />
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

      {menuOpen && <MenuOverlay onClose={() => setMenuOpen(false)} />}
    </div>
  );
}

export default App;
