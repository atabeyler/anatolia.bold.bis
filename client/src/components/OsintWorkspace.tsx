import { useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { apiErrorMessageKey } from '../services/apiClient';
import * as duplicatesClient from '../services/duplicatesClient';
import type { PossibleDuplicate } from '../services/duplicatesClient';
import * as entityGraphClient from '../services/entityGraphClient';
import { RELATION_TYPES } from '../services/entityGraphClient';
import type { EntityRelation, RelationType } from '../services/entityGraphClient';
import * as evidenceClient from '../services/evidenceClient';
import type { EvidenceItem } from '../services/evidenceClient';
import { Overlay } from './Overlay';

interface OsintWorkspaceProps {
  candidateId: string;
  candidateName: string;
  canManage: boolean;
  onClose: () => void;
}

type Section = 'evidence' | 'entityGraph' | 'duplicates';

/** Groups evidence by the source types emitted by the backend. Tavily's
 * query-related `web_image` results live under the existing Web group;
 * `reverse_image` remains reserved for an actual image-to-web provider.
 */
const EVIDENCE_SOURCE_GROUPS: Array<{ key: string; sourceTypes: string[] }> = [
  { key: 'web', sourceTypes: ['web_search', 'web_image'] },
  { key: 'news', sourceTypes: ['news'] },
  { key: 'social', sourceTypes: ['social'] },
  { key: 'reverseImage', sourceTypes: ['reverse_image'] },
];

export function OsintWorkspace({ candidateId, candidateName, canManage, onClose }: OsintWorkspaceProps) {
  const { t } = useTranslation();
  const [section, setSection] = useState<Section>('evidence');

  const [evidence, setEvidence] = useState<EvidenceItem[] | null>(null);
  const [evidenceError, setEvidenceError] = useState(false);
  const [collectQuery, setCollectQuery] = useState(candidateName);
  const [collecting, setCollecting] = useState(false);
  const [providerErrors, setProviderErrors] = useState<Array<{ provider: string; error: string }>>([]);
  const [collectMessage, setCollectMessage] = useState<string | null>(null);

  const [relations, setRelations] = useState<EntityRelation[] | null>(null);
  const [relationsError, setRelationsError] = useState(false);
  const [relationType, setRelationType] = useState<RelationType>('alias');
  const [relationValue, setRelationValue] = useState('');
  const [addingRelation, setAddingRelation] = useState(false);
  const [relationMessage, setRelationMessage] = useState<string | null>(null);

  const [duplicates, setDuplicates] = useState<PossibleDuplicate[] | null>(null);
  const [duplicatesError, setDuplicatesError] = useState(false);

  const loadEvidence = () => {
    setEvidenceError(false);
    evidenceClient
      .listEvidence(candidateId)
      .then(setEvidence)
      .catch(() => setEvidenceError(true));
  };

  const loadRelations = () => {
    setRelationsError(false);
    entityGraphClient
      .listEntityRelations(candidateId)
      .then(setRelations)
      .catch(() => setRelationsError(true));
  };

  const loadDuplicates = () => {
    setDuplicatesError(false);
    duplicatesClient
      .listPossibleDuplicates(candidateId)
      .then(setDuplicates)
      .catch(() => setDuplicatesError(true));
  };

  useEffect(() => {
    loadEvidence();
    loadRelations();
    loadDuplicates();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [candidateId]);

  const handleCollect = async (event: FormEvent) => {
    event.preventDefault();
    setCollecting(true);
    setCollectMessage(null);
    try {
      const result = await evidenceClient.collectEvidence(candidateId, collectQuery.trim());
      setProviderErrors(result.providerErrors);
      loadEvidence();
    } catch (error) {
      setCollectMessage(t(apiErrorMessageKey(error, 'errors.internal')) ?? '');
    } finally {
      setCollecting(false);
    }
  };

  const handleAddRelation = async (event: FormEvent) => {
    event.preventDefault();
    setAddingRelation(true);
    setRelationMessage(null);
    try {
      await entityGraphClient.addEntityRelation(candidateId, relationType, relationValue.trim());
      setRelationValue('');
      loadRelations();
    } catch (error) {
      setRelationMessage(t(apiErrorMessageKey(error, 'errors.internal')) ?? '');
    } finally {
      setAddingRelation(false);
    }
  };

  return (
    <Overlay title={t('osint.title', { name: candidateName })} onClose={onClose}>
      <div className="overlay-tabs">
        <button
          type="button"
          className={section === 'evidence' ? 'overlay-tabs__tab overlay-tabs__tab--active' : 'overlay-tabs__tab'}
          onClick={() => setSection('evidence')}
        >
          {t('osint.tabs.evidence')}
        </button>
        <button
          type="button"
          className={section === 'entityGraph' ? 'overlay-tabs__tab overlay-tabs__tab--active' : 'overlay-tabs__tab'}
          onClick={() => setSection('entityGraph')}
        >
          {t('osint.tabs.entityGraph')}
        </button>
        <button
          type="button"
          className={section === 'duplicates' ? 'overlay-tabs__tab overlay-tabs__tab--active' : 'overlay-tabs__tab'}
          onClick={() => setSection('duplicates')}
        >
          {t('osint.tabs.duplicates')}
        </button>
      </div>

      {section === 'evidence' && (
        <div className="overlay-content">
          {canManage && (
            <form onSubmit={handleCollect} className="admin-form-row">
              <input
                type="text"
                value={collectQuery}
                onChange={(event) => setCollectQuery(event.target.value)}
                placeholder={t('osint.evidence.queryPlaceholder') ?? ''}
                aria-label={t('osint.evidence.queryPlaceholder') ?? ''}
                required
              />
              <button type="submit" className="admin-submit" disabled={collecting}>
                {t('osint.evidence.collect')}
              </button>
            </form>
          )}
          {collectMessage && <p className="auth-message auth-message--error">{collectMessage}</p>}
          {providerErrors.length > 0 && (
            <p className="admin-hint">
              {t('osint.evidence.providerErrors', {
                providers: providerErrors.map((e) => e.provider).join(', '),
              })}
            </p>
          )}
          {evidence === null && !evidenceError && <p className="status-card__line">{t('admin.loading')}</p>}
          {evidenceError && <p className="status-card__line status-card__line--offline">{t('admin.loadError')}</p>}
          {evidence !== null && evidence.length === 0 && (
            <p className="status-card__line">{t('osint.evidence.empty')}</p>
          )}
          {EVIDENCE_SOURCE_GROUPS.map(({ key, sourceTypes }) => {
            const items = evidence?.filter((item) => sourceTypes.includes(item.sourceType)) ?? [];
            if (items.length === 0) return null;
            return (
              <div key={key}>
                <h3 className="overlay-content__heading">
                  {t(`osint.evidence.group.${key}`, { count: items.length })}
                </h3>
                <ul className="overlay-list">
                  {items.map((item) => (
                    <li key={item.id} className="overlay-list__item overlay-list__item--session">
                      <div>
                        <div>{item.title ?? item.snippet ?? item.url ?? item.providerName}</div>
                        <div className="admin-user-card__note">
                          {item.providerName.startsWith('mock-')
                            ? t('osint.status.mock')
                            : item.providerName}
                          {item.url ? ` · ${item.url}` : ''}
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      )}

      {section === 'entityGraph' && (
        <div className="overlay-content">
          {canManage && (
            <form onSubmit={handleAddRelation} className="admin-form-row">
              <select value={relationType} onChange={(event) => setRelationType(event.target.value as RelationType)}>
                {RELATION_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {t(`osint.entityGraph.relationType.${type}`)}
                  </option>
                ))}
              </select>
              <input
                type="text"
                value={relationValue}
                onChange={(event) => setRelationValue(event.target.value)}
                placeholder={t('osint.entityGraph.valuePlaceholder') ?? ''}
                aria-label={t('osint.entityGraph.valuePlaceholder') ?? ''}
                required
              />
              <button type="submit" className="admin-submit" disabled={addingRelation}>
                {t('osint.entityGraph.add')}
              </button>
            </form>
          )}
          {relationMessage && <p className="auth-message auth-message--error">{relationMessage}</p>}
          {relations === null && !relationsError && <p className="status-card__line">{t('admin.loading')}</p>}
          {relationsError && <p className="status-card__line status-card__line--offline">{t('admin.loadError')}</p>}
          {relations !== null && relations.length === 0 && (
            <p className="status-card__line">{t('osint.entityGraph.empty')}</p>
          )}
          <ul className="overlay-list">
            {relations?.map((relation) => (
              <li key={relation.id} className="overlay-list__item overlay-list__item--session">
                <div>
                  <div>{relation.value}</div>
                  <div className="admin-user-card__note">
                    {t(`osint.entityGraph.relationType.${relation.relationType}`)}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {section === 'duplicates' && (
        <div className="overlay-content">
          {duplicates === null && !duplicatesError && <p className="status-card__line">{t('admin.loading')}</p>}
          {duplicatesError && <p className="status-card__line status-card__line--offline">{t('admin.loadError')}</p>}
          {duplicates !== null && duplicates.length === 0 && (
            <p className="status-card__line">{t('osint.duplicates.empty')}</p>
          )}
          <ul className="overlay-list">
            {duplicates?.map((dup) => (
              <li key={dup.candidateId} className="overlay-list__item overlay-list__item--session">
                <div>
                  <div>
                    {dup.fullName} ({dup.referenceCode})
                  </div>
                  <div className="admin-user-card__note">{dup.matchedSignals.join(', ')}</div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Overlay>
  );
}
