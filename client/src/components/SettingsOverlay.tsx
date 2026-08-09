import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { LANGUAGE_NAMES, SUPPORTED_LANGUAGES } from '../i18n/config';
import { isSoundEnabled, playChime, setSoundEnabled } from '../lib/sound';
import { applyTheme, getStoredTheme, type Theme } from '../lib/theme';
import { Overlay } from './Overlay';

type Tab = 'language' | 'sound' | 'appearance' | 'about';

const TABS: Array<{ id: Tab; labelKey: string }> = [
  { id: 'language', labelKey: 'settings.tabs.language' },
  { id: 'sound', labelKey: 'settings.tabs.sound' },
  { id: 'appearance', labelKey: 'settings.tabs.appearance' },
  { id: 'about', labelKey: 'settings.tabs.about' },
];

interface SettingsOverlayProps {
  onClose: () => void;
  onBack?: () => void;
}

export function SettingsOverlay({ onClose, onBack }: SettingsOverlayProps) {
  const { t, i18n } = useTranslation();
  const [tab, setTab] = useState<Tab>('language');
  const [soundEnabled, setSoundEnabledState] = useState(isSoundEnabled());
  const [theme, setTheme] = useState<Theme>(getStoredTheme());

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
