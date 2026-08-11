import i18n from 'i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import { initReactI18next } from 'react-i18next';

import arEnrollment from './enrollment/ar.json';
import deEnrollment from './enrollment/de.json';
import enEnrollment from './enrollment/en.json';
import frEnrollment from './enrollment/fr.json';
import ruEnrollment from './enrollment/ru.json';
import trEnrollment from './enrollment/tr.json';
import ar from './locales/ar/translation.json';
import de from './locales/de/translation.json';
import en from './locales/en/translation.json';
import fr from './locales/fr/translation.json';
import ru from './locales/ru/translation.json';
import tr from './locales/tr/translation.json';
import arResultGroups from './result-groups/ar.json';
import deResultGroups from './result-groups/de.json';
import enResultGroups from './result-groups/en.json';
import frResultGroups from './result-groups/fr.json';
import ruResultGroups from './result-groups/ru.json';
import trResultGroups from './result-groups/tr.json';

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
      en: {
        translation: {
          ...en,
          ...enEnrollment,
          ...enResultGroups,
          search: { ...en.search, subtitle: enResultGroups.resultGroups.biometric },
        },
      },
      tr: {
        translation: {
          ...tr,
          ...trEnrollment,
          ...trResultGroups,
          search: { ...tr.search, subtitle: trResultGroups.resultGroups.biometric },
        },
      },
      de: {
        translation: {
          ...de,
          ...deEnrollment,
          ...deResultGroups,
          search: { ...de.search, subtitle: deResultGroups.resultGroups.biometric },
        },
      },
      fr: {
        translation: {
          ...fr,
          ...frEnrollment,
          ...frResultGroups,
          search: { ...fr.search, subtitle: frResultGroups.resultGroups.biometric },
        },
      },
      ar: {
        translation: {
          ...ar,
          ...arEnrollment,
          ...arResultGroups,
          search: { ...ar.search, subtitle: arResultGroups.resultGroups.biometric },
        },
      },
      ru: {
        translation: {
          ...ru,
          ...ruEnrollment,
          ...ruResultGroups,
          search: { ...ru.search, subtitle: ruResultGroups.resultGroups.biometric },
        },
      },
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
