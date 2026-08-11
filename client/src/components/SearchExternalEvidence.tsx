import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';

import type { SearchExternalEvidenceItem } from '../services/searchClient';

interface SearchExternalEvidenceProps {
  items: SearchExternalEvidenceItem[];
}

type EvidenceGroup = 'visualSource' | 'visualSimilarity' | 'openSource' | 'crossSource';

function normalizeUrl(url: string | null): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    parsed.hash = '';
    parsed.hostname = parsed.hostname.toLowerCase();
    if (parsed.pathname !== '/') parsed.pathname = parsed.pathname.replace(/\/+$/, '');
    return parsed.toString();
  } catch {
    return url.trim().replace(/\/+$/, '').toLowerCase();
  }
}

function evidenceKey(item: SearchExternalEvidenceItem): string {
  return [item.sourceType, normalizeUrl(item.url) ?? '', item.title].join('|');
}

function isDirectVisualMatch(item: SearchExternalEvidenceItem): boolean {
  if (item.sourceType !== 'reverse_image') return false;
  const text = `${item.title} ${item.snippet ?? ''}`.toLowerCase();
  return (
    item.providerName.includes('tineye') ||
    text.includes('full image match') ||
    text.includes('full matching image') ||
    text.includes('partial image match') ||
    text.includes('partial matching image') ||
    text.includes('matched image')
  );
}

function groupFor(item: SearchExternalEvidenceItem): EvidenceGroup | null {
  if (item.sourceType === 'reverse_image') {
    return isDirectVisualMatch(item) ? 'visualSource' : 'visualSimilarity';
  }
  if (
    item.sourceType === 'web_search' ||
    item.sourceType === 'web_image' ||
    item.sourceType === 'news' ||
    item.sourceType === 'social'
  ) {
    return 'openSource';
  }
  return null;
}

function crossSourceItems(items: SearchExternalEvidenceItem[]): Array<SearchExternalEvidenceItem & { sourceCount: number }> {
  const byUrl = new Map<string, { item: SearchExternalEvidenceItem; providers: Set<string> }>();
  for (const item of items) {
    const url = normalizeUrl(item.url);
    if (!url) continue;
    const current = byUrl.get(url);
    if (current) {
      current.providers.add(item.providerName);
    } else {
      byUrl.set(url, { item, providers: new Set([item.providerName]) });
    }
  }
  return [...byUrl.values()]
    .filter(({ providers }) => providers.size > 1)
    .map(({ item, providers }) => ({ ...item, sourceCount: providers.size }))
    .sort((a, b) => b.sourceCount - a.sourceCount);
}

export function SearchExternalEvidence({ items }: SearchExternalEvidenceProps) {
  const { t } = useTranslation();
  const { groups, corroborated } = useMemo(() => {
    const seen = new Set<string>();
    const grouped: Record<Exclude<EvidenceGroup, 'crossSource'>, SearchExternalEvidenceItem[]> = {
      visualSource: [],
      visualSimilarity: [],
      openSource: [],
    };

    for (const item of items) {
      const key = evidenceKey(item);
      if (seen.has(key)) continue;
      seen.add(key);
      const group = groupFor(item);
      if (group && group !== 'crossSource') grouped[group].push(item);
    }

    for (const groupItems of Object.values(grouped)) {
      groupItems.sort((a, b) => b.confidenceScore - a.confidenceScore);
    }

    return { groups: grouped, corroborated: crossSourceItems(items) };
  }, [items]);

  const sections: Array<{
    key: Exclude<EvidenceGroup, 'crossSource'>;
    titleKey: string;
    noteKey: string;
  }> = [
    {
      key: 'visualSource',
      titleKey: 'resultGroups.visualSource',
      noteKey: 'resultGroups.visualSourceNote',
    },
    {
      key: 'visualSimilarity',
      titleKey: 'resultGroups.visualSimilarity',
      noteKey: 'resultGroups.visualSimilarityNote',
    },
    {
      key: 'openSource',
      titleKey: 'resultGroups.openSource',
      noteKey: 'resultGroups.openSourceNote',
    },
  ];

  const renderItem = (item: SearchExternalEvidenceItem, sourceCount?: number) => (
    <article key={`${evidenceKey(item)}-${sourceCount ?? 1}`} className="admin-user-card">
      <div className="admin-user-card__row">
        <div className="admin-user-card__info">
          <div className="admin-user-card__name">
            <span>{item.title}</span>
          </div>
          {item.snippet && <p className="admin-user-card__note">{item.snippet}</p>}
          {sourceCount && sourceCount > 1 && (
            <p className="admin-user-card__note">
              {t('resultGroups.independentSources', { count: sourceCount })}
            </p>
          )}
          {item.url && (
            <a
              className="overlay-secondary-button"
              href={item.url}
              target="_blank"
              rel="noopener noreferrer"
            >
              {t('resultGroups.openSourcePage')}
            </a>
          )}
        </div>
      </div>
    </article>
  );

  return (
    <>
      {sections.map(({ key, titleKey, noteKey }) => {
        const sectionItems = groups[key];
        if (sectionItems.length === 0) return null;
        return (
          <section key={key} className="admin-user-list" aria-label={t(titleKey)}>
            <h3 className="admin-panel__heading">{t(titleKey)}</h3>
            <p className="admin-hint">{t(noteKey)}</p>
            {sectionItems.map((item) => renderItem(item))}
          </section>
        );
      })}

      {corroborated.length > 0 && (
        <section className="admin-user-list" aria-label={t('resultGroups.crossSource')}>
          <h3 className="admin-panel__heading">{t('resultGroups.crossSource')}</h3>
          <p className="admin-hint">{t('resultGroups.crossSourceNote')}</p>
          {corroborated.map((item) => renderItem(item, item.sourceCount))}
        </section>
      )}
    </>
  );
}
