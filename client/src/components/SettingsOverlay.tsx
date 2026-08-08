import { useTranslation } from 'react-i18next';

import { LANGUAGE_NAMES, SUPPORTED_LANGUAGES } from '../i18n/config';
import { Overlay } from './Overlay';

interface SettingsOverlayProps {
  onClose: () => void;
}

export function SettingsOverlay({ onClose }: SettingsOverlayProps) {
  const { t, i18n } = useTranslation();

  return (
    <Overlay title={t('settings.title')} onClose={onClose}>
      <p className="overlay-section-label">{t('settings.language')}</p>
      <ul className="overlay-list">
        {SUPPORTED_LANGUAGES.map((language) => (
          <li key={language}>
            <button
              type="button"
              className="overlay-list__item"
              onClick={() => void i18n.changeLanguage(language)}
            >
              <span>{LANGUAGE_NAMES[language]}</span>
              {i18n.resolvedLanguage === language && <span aria-hidden="true">✓</span>}
            </button>
          </li>
        ))}
      </ul>
    </Overlay>
  );
}
