import i18n from 'i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import { initReactI18next } from 'react-i18next';

import ar from './locales/ar/translation.json';
import de from './locales/de/translation.json';
import en from './locales/en/translation.json';
import fr from './locales/fr/translation.json';
import ru from './locales/ru/translation.json';
import tr from './locales/tr/translation.json';

export const SUPPORTED_LANGUAGES = ['en', 'tr', 'de', 'fr', 'ar', 'ru'] as const;
export type SupportedLanguage = (typeof SUPPORTED_LANGUAGES)[number];

export const LANGUAGE_NAMES: Record<SupportedLanguage, string> = {
  en: 'English',
  tr: 'Türkçe',
  de: 'Deutsch',
  fr: 'Français',
  ar: 'العربية',
  ru: 'Русский',
};

const RTL_LANGUAGES: ReadonlySet<SupportedLanguage> = new Set(['ar']);

export function textDirectionFor(language: string): 'rtl' | 'ltr' {
  return RTL_LANGUAGES.has(language as SupportedLanguage) ? 'rtl' : 'ltr';
}

export function applyDocumentDirection(language: string): void {
  document.documentElement.lang = language;
  document.documentElement.dir = textDirectionFor(language);
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      tr: { translation: tr },
      de: { translation: de },
      fr: { translation: fr },
      ar: { translation: ar },
      ru: { translation: ru },
    },
    supportedLngs: SUPPORTED_LANGUAGES,
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false,
    },
  });

applyDocumentDirection(i18n.resolvedLanguage ?? 'en');
i18n.on('languageChanged', applyDocumentDirection);

export default i18n;
