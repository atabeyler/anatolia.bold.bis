import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';

import type { SearchExternalEvidenceItem } from '../services/searchClient';

interface SearchExternalEvidenceProps {
  items: SearchExternalEvidenceItem[];
}

type EvidenceGroup = 'reverse' | 'web' | 'news';

function evidenceKey(item: SearchExternalEvidenceItem): string {
  return [item.providerName, item.sourceType, item.url ?? '', item.title].join('|');
}

function groupFor(item: SearchExternalEvidenceItem): EvidenceGroup | null {
  if (item.sourceType === 'reverse_image') return 'reverse';
  if (item.sourceType === 'web_search' || item.sourceType === 'web_image') return 'web';
  if (item.sourceType === 'news') return 'news';
  return null;
}

function reverseRank(item: SearchExternalEvidenceItem): number {
  const text = `${item.title} ${item.snippet ?? ''}`.toLowerCase();
  if (text.includes('full image match') || text.includes('full matching image')) return 0;
  if (text.includes('partial image match') || text.includes('partial matching image')) return 1;
  if (text.includes('visually similar image')) return 2;
  return 3;
}

function reverseImageCopy(language: string): { title: string; note: string } {
  const normalized = language.toLowerCase();
  if (normalized.startsWith('tr')) {
    return {
      title: 'İnternet görsel eşleşmeleri',
      note: 'Aynı veya kısmi görsel eşleşmesidir; yüz kimliği eşleşmesi değildir.',
    };
  }
  if (normalized.startsWith('de')) {
    return {
      title: 'Internet-Bildtreffer',
      note: 'Dies ist ein vollständiger oder teilweiser Bildtreffer, kein biometrischer Identitätsabgleich.',
    };
  }
  if (normalized.startsWith('fr')) {
    return {
      title: 'Correspondances d’images sur Internet',
      note: 'Il s’agit d’une correspondance d’image complète ou partielle, et non d’une correspondance biométrique d’identité.',
    };
  }
  if (normalized.startsWith('ar')) {
    return {
      title: 'مطابقات الصور على الإنترنت',
      note: 'هذه مطابقة كاملة أو جزئية للصورة وليست مطابقة بيومترية للهوية.',
    };
  }
  if (normalized.startsWith('ru')) {
    return {
      title: 'Совпадения изображений в интернете',
      note: 'Это полное или частичное совпадение изображения, а не биометрическое подтверждение личности.',
    };
  }
  return {
    title: 'Internet image matches',
    note: 'This is a full or partial image match, not a biometric identity match.',
  };
}

export function SearchExternalEvidence({ items }: SearchExternalEvidenceProps) {
  const { t, i18n } = useTranslation();
  const reverseCopy = reverseImageCopy(i18n.resolvedLanguage ?? i18n.language ?? 'en');
  const groupedItems = useMemo(() => {
    const seen = new Set<string>();
    const groups: Record<EvidenceGroup, SearchExternalEvidenceItem[]> = {
      reverse: [],
      web: [],
      news: [],
    };

    items.forEach((item) => {
      const key = evidenceKey(item);
      if (seen.has(key)) return;
      seen.add(key);
      const group = groupFor(item);
      if (group) groups[group].push(item);
    });

    groups.reverse.sort((a, b) => reverseRank(a) - reverseRank(b));
    return groups;
  }, [items]);

  const sections: Array<{ key: EvidenceGroup; title: string }> = [
    { key: 'reverse', title: reverseCopy.title },
    { key: 'web', title: t('search.externalEvidence.web') },
    { key: 'news', title: t('search.externalEvidence.news') },
  ];

  return (
    <>
      {sections.map(({ key, title }) => {
        const sectionItems = groupedItems[key];
        if (sectionItems.length === 0) return null;
        return (
          <section key={key} className="admin-user-list" aria-label={title}>
            <h3 className="admin-panel__heading">{title}</h3>
            {key === 'reverse' && <p className="admin-hint">{reverseCopy.note}</p>}
            {sectionItems.map((item) => (
              <article key={evidenceKey(item)} className="admin-user-card">
                <div className="admin-user-card__row">
                  <div className="admin-user-card__info">
                    <div className="admin-user-card__name">
                      <span>{item.title}</span>
                      <span className="admin-user-card__separator">·</span>
                      <span>{item.providerName}</span>
                    </div>
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
      })}
    </>
  );
}
