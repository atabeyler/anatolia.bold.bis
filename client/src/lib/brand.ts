/** Turkish renders the brand mark with a dotted İ, matching the
 * company's other product's own per-locale convention; every other
 * supported language uses the plain Latin form. */
export function brandMark(language: string | undefined): string {
  return language === 'tr' ? 'ANATOLİA-BİS' : 'ANATOLIA-BIS';
}
