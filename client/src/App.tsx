import { useTranslation } from 'react-i18next';

import { LanguageSwitcher } from './components/LanguageSwitcher';
import { DashboardPage } from './pages/DashboardPage';

function App() {
  const { t } = useTranslation();

  return (
    <div className="app-shell">
      <header className="app-header">
        <div>
          <h1>{t('app.title')}</h1>
          <p className="app-header__tagline">{t('app.tagline')}</p>
        </div>
        <LanguageSwitcher />
      </header>

      <DashboardPage />

      <footer className="app-footer">
        <p>{t('footer.foundationStage')}</p>
      </footer>
    </div>
  );
}

export default App;
