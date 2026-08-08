import { useTranslation } from 'react-i18next';

import { SUPPORTED_LANGUAGES } from '../i18n/config';

const LANGUAGE_NAMES: Record<(typeof SUPPORTED_LANGUAGES)[number], string> = {
  en: 'English',
  tr: 'Türkçe',
  de: 'Deutsch',
  fr: 'Français',
  ar: 'العربية',
  ru: 'Русский',
};

export function LanguageSwitcher() {
  const { t, i18n } = useTranslation();

  return (
    <label className="language-switcher">
      <span className="language-switcher__label">{t('language.label')}</span>
      <select
        value={i18n.resolvedLanguage}
        onChange={(event) => {
          void i18n.changeLanguage(event.target.value);
        }}
      >
        {SUPPORTED_LANGUAGES.map((language) => (
          <option key={language} value={language}>
            {LANGUAGE_NAMES[language]}
          </option>
        ))}
      </select>
    </label>
  );
}
