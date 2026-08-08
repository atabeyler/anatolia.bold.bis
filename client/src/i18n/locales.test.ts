import { describe, expect, it } from 'vitest';

import ar from './locales/ar/translation.json';
import de from './locales/de/translation.json';
import en from './locales/en/translation.json';
import fr from './locales/fr/translation.json';
import ru from './locales/ru/translation.json';
import tr from './locales/tr/translation.json';

const locales: Record<string, unknown> = { tr, de, fr, ar, ru };

function collectKeyPaths(value: unknown, prefix = ''): string[] {
  if (typeof value !== 'object' || value === null) {
    return [prefix];
  }
  return Object.entries(value as Record<string, unknown>).flatMap(([key, nested]) =>
    collectKeyPaths(nested, prefix ? `${prefix}.${key}` : key),
  );
}

const englishKeyPaths = collectKeyPaths(en).sort();

describe('locale key trees', () => {
  it.each(Object.entries(locales))('%s matches the English locale key tree', (_locale, resource) => {
    expect(collectKeyPaths(resource).sort()).toEqual(englishKeyPaths);
  });
});
