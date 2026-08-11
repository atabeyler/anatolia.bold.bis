import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';

import type { SearchExternalEvidenceItem } from '../services/searchClient';

interface SearchExternalEvidenceProps {
  items: SearchExternalEvidenceItem[];
}

function evidenceKey(item: SearchExternalEvidenceItem): string {
  return [item.providerName, item.sourceType, item.url ?? '', item.title].join('|');
}

export function SearchExternalEvidence({ items }: SearchExternalEvidenceProps) {
  const { t } = useTranslation();
  const uniqueItems = useMemo(() => {
    const seen = new Set<string>();
    return items.filter((item) => {
      const key = evidenceKey(item);
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [items]);

  if (uniqueItems.length === 0) return null;

  return (
    <section className="admin-user-list" aria-label={t('search.externalEvidence.reverseImage')}>
      <h3 className="admin-panel__heading">{t('search.externalEvidence.reverseImage')}</h3>
      {uniqueItems.map((item) => (
        <article key={evidenceKey(item)} className="admin-user-card">
          <div className="admin-user-card__row">
            <div className="admin-user-card__info">
              <div className="admin-user-card__name">
                <span>{item.title}</span>
                <span className="admin-user-card__separator">·</span>
                <span>{item.providerName}</span>
              </div>
              <p className="admin-user-card__note">{item.sourceType}</p>
              {item.snippet && <p className="admin-user-card__note">{item.snippet}</p>}
              {item.url && (
                <a
                  className="overlay-secondary-button"
                  href={item.url}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {item.url}
                </a>
              )}
            </div>
          </div>
        </article>
      ))}
    </section>
  );
}
