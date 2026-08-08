import { useTranslation } from 'react-i18next';

import { LanguageSwitcher } from './components/LanguageSwitcher';
import { useAuth } from './features/auth/AuthContext';
import { DashboardPage } from './pages/DashboardPage';
import { LoginPage } from './pages/LoginPage';

function App() {
  const { t } = useTranslation();
  const { user, status, logout } = useAuth();

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
          <LanguageSwitcher />
        </div>
      </header>

      {status === 'loading' ? null : status === 'signed-in' ? <DashboardPage /> : <LoginPage />}

      <footer className="app-footer">
        <p>{t('footer.legal')}</p>
      </footer>
    </div>
  );
}

export default App;
