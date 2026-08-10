import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Logo } from './components/Logo';
import { MenuOverlay } from './components/MenuOverlay';
import { RecoveryCodesModal } from './components/RecoveryCodesModal';
import { useAuth } from './features/auth/AuthContext';
import { brandMark } from './lib/brand';
import { AdminPage } from './pages/AdminPage';
import { AuditPage } from './pages/AuditPage';
import { DashboardPage } from './pages/DashboardPage';
import { LoginPage } from './pages/LoginPage';
import { ResetPasswordPage } from './pages/ResetPasswordPage';

const ADMIN_ROLES = ['SYSTEM_ADMIN', 'SECURITY_ADMIN'];
const AUDIT_ROLES = ['SYSTEM_ADMIN', 'SECURITY_ADMIN', 'AUDITOR'];

type View = 'dashboard' | 'admin' | 'audit';

function App() {
  const { t, i18n } = useTranslation();
  const { status, user, logout, pendingRecoveryCodes, acknowledgeRecoveryCodes } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [view, setView] = useState<View | null>(null);
  const [resetToken, setResetToken] = useState<string | null>(
    () => new URLSearchParams(window.location.search).get('resetToken'),
  );
  const isAdmin = !!user && ADMIN_ROLES.includes(user.role);
  const canViewAudit = !!user && AUDIT_ROLES.includes(user.role);
  const signedIn = status === 'signed-in';

  const topbarRef = useRef<HTMLElement | null>(null);
  const footerRef = useRef<HTMLElement | null>(null);

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

  // .app-main's clearance for the fixed top bar and footer is measured
  // live, not assumed from a fixed rem value: on narrow screens, or in
  // languages whose strings are longer than English, the bar wraps onto
  // extra lines and grows taller. A static padding guess would then let
  // content hide underneath it.
  //
  // ResizeObserver drives most updates, but it can miss the one resize
  // that matters most here: the brand/mono webfonts load asynchronously
  // (see index.html's Google Fonts link) and swap in after first paint,
  // which reflows both bars' text wrapping without reliably re-firing the
  // observer in every engine. `document.fonts.ready` plus a plain
  // `resize` listener are cheap, redundant correction passes that catch
  // exactly that case, so the reserved space never goes stale.
  useEffect(() => {
    const root = document.documentElement;
    const footerEl = footerRef.current;
    const topbarEl = topbarRef.current;

    const measure = () => {
      if (footerEl) {
        root.style.setProperty('--footer-height', `${Math.ceil(footerEl.getBoundingClientRect().height)}px`);
      }
      root.style.setProperty('--topbar-height', topbarEl ? `${Math.ceil(topbarEl.getBoundingClientRect().height)}px` : '0px');
    };

    measure();

    const footerObserver = new ResizeObserver(measure);
    if (footerEl) footerObserver.observe(footerEl);
    const topbarObserver = new ResizeObserver(measure);
    if (topbarEl) topbarObserver.observe(topbarEl);

    window.addEventListener('resize', measure);
    document.fonts?.ready.then(measure).catch(() => {});

    return () => {
      footerObserver.disconnect();
      topbarObserver.disconnect();
      window.removeEventListener('resize', measure);
    };
  }, [signedIn]);

  const clearResetToken = () => {
    const url = new URL(window.location.href);
    url.searchParams.delete('resetToken');
    window.history.replaceState({}, '', url.toString());
    setResetToken(null);
  };

  if (resetToken) {
    return (
      <div className="app-shell">
        <a href="#main-content" className="skip-link">
          {t('a11y.skipToContent')}
        </a>
        <div className="app-nav-fixed">
          <button type="button" className="app-header__nav-button" onClick={() => setMenuOpen(true)}>
            ☰ {t('menu.openLabel')}
          </button>
        </div>
        <div id="main-content" className="app-main">
          <ResetPasswordPage token={resetToken} onDone={clearResetToken} />
        </div>
        <footer className="app-footer" ref={footerRef}>
          <span className="footer-bar-text">
            {t('footer.legalCode')} · <span className="footer-bar-company">{t('footer.legalCompany')}</span>
            <span className="footer-bar-rights">{t('footer.legalRights')}</span>
          </span>
        </footer>
        {menuOpen && <MenuOverlay onClose={() => setMenuOpen(false)} />}
      </div>
    );
  }

  return (
    <div className="app-shell">
      <a href="#main-content" className="skip-link">
        {t('a11y.skipToContent')}
      </a>
      {signedIn ? (
        // Logo, brand, contextual subtitle, and session actions stay
        // pinned in one bar across every signed-in screen, rather than
        // scrolling away with page content (see .app-topbar).
        <header className="app-topbar" ref={topbarRef}>
          <div className="app-topbar__brand">
            <Logo compact />
            <div>
              <div className="app-topbar__title">{brandMark(i18n.resolvedLanguage)}</div>
              <div className="app-topbar__subtitle">
                {view === 'admin' ? t('admin.panelTitle') : view === 'audit' ? t('audit.panelTitle') : t('search.subtitle')}
              </div>
            </div>
          </div>
          <div className="app-topbar__actions">
            {view === 'admin' || view === 'audit' ? (
              <div className="app-header__session">
                <button
                  type="button"
                  className="app-header__nav-button"
                  onClick={() => setView('dashboard')}
                  aria-label={t('admin.goHome')}
                >
                  <span aria-hidden="true">←</span> <span className="topbar-label">{t('admin.goHome')}</span>
                </button>
                <button type="button" onClick={() => void logout()} aria-label={t('auth.logout')}>
                  <span aria-hidden="true">⏻</span> <span className="topbar-label">{t('auth.logout')}</span>
                </button>
              </div>
            ) : (
              user && (
                <div className="app-header__session">
                  {isAdmin && (
                    <button type="button" onClick={() => setView('admin')} aria-label={t('admin.openLabel')}>
                      <span aria-hidden="true">⚙</span> <span className="topbar-label">{t('admin.openLabel')}</span>
                    </button>
                  )}
                  {canViewAudit && (
                    <button type="button" onClick={() => setView('audit')} aria-label={t('audit.openLabel')}>
                      <span aria-hidden="true">▤</span> <span className="topbar-label">{t('audit.openLabel')}</span>
                    </button>
                  )}
                  <button type="button" onClick={() => void logout()} aria-label={t('auth.logout')}>
                    <span aria-hidden="true">⏻</span> <span className="topbar-label">{t('auth.logout')}</span>
                  </button>
                </div>
              )
            )}
            <button
              type="button"
              className="app-header__nav-button"
              onClick={() => setMenuOpen(true)}
              aria-label={t('menu.openLabel')}
            >
              ☰ <span className="topbar-label">{t('menu.openLabel')}</span>
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

      <div id="main-content" className={signedIn ? 'app-main app-main--with-topbar' : 'app-main'}>
        {status === 'loading' ? null : signedIn ? (
          view === 'admin' ? <AdminPage /> : view === 'audit' ? <AuditPage /> : <DashboardPage />
        ) : (
          <LoginPage />
        )}
      </div>

      <footer className="app-footer" ref={footerRef}>
        <span className="footer-bar-text">
          {t('footer.legalCode')} · <span className="footer-bar-company">{t('footer.legalCompany')}</span>
          <span className="footer-bar-rights">{t('footer.legalRights')}</span>
        </span>
      </footer>

      {menuOpen && <MenuOverlay onClose={() => setMenuOpen(false)} />}
      {pendingRecoveryCodes && (
        <RecoveryCodesModal codes={pendingRecoveryCodes} onAcknowledge={acknowledgeRecoveryCodes} />
      )}
    </div>
  );
}

export default App;
