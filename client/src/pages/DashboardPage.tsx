import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { OsintWorkspace } from '../components/OsintWorkspace';
import { SearchExternalEvidence } from '../components/SearchExternalEvidence';
import { useAuth } from '../features/auth/AuthContext';
import { formatLatitude, formatLongitude, getLastKnownLocation } from '../hooks/useGeolocation';
import * as searchClient from '../services/searchClient';
import type { SearchCandidate, SearchSummary } from '../services/searchClient';
import * as evidenceClient from '../services/evidenceClient';
import { apiErrorMessageKey } from '../services/apiClient';
import { getHealthReady } from '../services/systemClient';

const REVIEW_ROLES = ['REVIEWER', 'SECURITY_ADMIN', 'SYSTEM_ADMIN'];
const SEARCH_ROLES = ['OPERATOR', 'REVIEWER', 'SECURITY_ADMIN', 'SYSTEM_ADMIN'];
const MANAGE_CANDIDATE_ROLES = ['OPERATOR', 'SECURITY_ADMIN', 'SYSTEM_ADMIN'];

export function DashboardPage() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const canReview = !!user && REVIEW_ROLES.includes(user.role);
  const canSearch = !!user && SEARCH_ROLES.includes(user.role);
  const canManageCandidates = !!user && MANAGE_CANDIDATE_ROLES.includes(user.role);
  const [osintCandidate, setOsintCandidate] = useState<{ id: string; name: string } | null>(null);

  const [caseReference, setCaseReference] = useState('');
  const [purpose, setPurpose] = useState('');
  const [image, setImage] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formErrorKey, setFormErrorKey] = useState<string | null>(null);

  const [activeSearch, setActiveSearch] = useState<SearchSummary | null>(null);
  const [activeCandidates, setActiveCandidates] = useState<SearchCandidate[]>([]);
  const [activeCandidatesLoading, setActiveCandidatesLoading] = useState(false);
  const [activeCandidatesError, setActiveCandidatesError] = useState(false);
  const [reviewBusyId, setReviewBusyId] = useState<string | null>(null);
  const [reviewErrorKey, setReviewErrorKey] = useState<string | null>(null);
  const [evidenceCounts, setEvidenceCounts] = useState<Record<string, number>>({});

  const [pastSearches, setPastSearches] = useState<SearchSummary[] | null>(null);
  const [pastSearchesError, setPastSearchesError] = useState(false);
  const [isMockProvider, setIsMockProvider] = useState<boolean | null>(null);

  useEffect(() => {
    getHealthReady()
      .then((health) => setIsMockProvider(health.biometricProvider === 'mock'))
      .catch(() => setIsMockProvider(null));
  }, []);

  const loadPastSearches = () => {
    setPastSearchesError(false);
    searchClient
      .listSearches()
      .then((page) => setPastSearches(page.items))
      .catch(() => setPastSearchesError(true));
  };

  useEffect(() => {
    loadPastSearches();
  }, []);

  const loadEvidenceCounts = (candidates: SearchCandidate[]) => {
    setEvidenceCounts({});
    candidates.forEach((candidate) => {
      evidenceClient
        .listEvidence(candidate.candidateId)
        .then((items) => {
          setEvidenceCounts((counts) => ({
            ...counts,
            [candidate.candidateId]: items.length,
          }));
        })
        .catch(() => undefined);
    });
  };

  const openSearch = async (search: SearchSummary) => {
    setActiveSearch(search);
    setActiveCandidates([]);
    setActiveCandidatesError(false);
    setActiveCandidatesLoading(true);
    try {
      const candidates = await searchClient.getSearchCandidates(search.id);
      setActiveCandidates(candidates);
      loadEvidenceCounts(candidates);
    } catch {
      setActiveCandidatesError(true);
    } finally {
      setActiveCandidatesLoading(false);
    }
  };

  const handleCreateSearch = async (event: FormEvent) => {
    event.preventDefault();
    if (!image) {
      setFormErrorKey('errors.validation');
      return;
    }
    setFormErrorKey(null);
    setSubmitting(true);
    try {
      const result = await searchClient.createSearch(
        caseReference.trim(),
        purpose.trim(),
        image,
        getLastKnownLocation(),
      );
      if (result.search.status === 'failed') {
        setFormErrorKey(result.search.failureMessageKey ?? 'search.createError');
      } else {
        setActiveSearch(result.search);
        setActiveCandidates(result.candidates);
        loadEvidenceCounts(result.candidates);
        setCaseReference('');
        setPurpose('');
        setImage(null);
        if (fileInputRef.current) fileInputRef.current.value = '';
      }
      loadPastSearches();
    } catch (error) {
      setFormErrorKey(apiErrorMessageKey(error, 'search.createError'));
    } finally {
      setSubmitting(false);
    }
  };

  const runReview = async (candidateId: string, action: 'confirm' | 'reject' | 'inconclusive') => {
    if (!activeSearch) return;
    setReviewBusyId(candidateId);
    setReviewErrorKey(null);
    try {
      const updated =
        action === 'confirm'
          ? await searchClient.verifyCandidate(candidateId, activeSearch.id)
          : action === 'reject'
            ? await searchClient.rejectCandidate(candidateId, activeSearch.id)
            : await searchClient.markCandidateInconclusive(candidateId, activeSearch.id);
      setActiveCandidates((rows) =>
        rows.map((row) => (row.candidateId === candidateId ? updated : row)),
      );
    } catch (error) {
      setReviewErrorKey(apiErrorMessageKey(error));
    } finally {
      setReviewBusyId(null);
    }
  };

  return (
    <main className="admin-page">
      <nav className="admin-tabs">
        <span className="admin-tabs__tab admin-tabs__tab--active">{t('search.tabSearch')}</span>
      </nav>

      {canSearch ? (
        <section className="admin-panel">
          <h2 className="admin-panel__heading">{t('search.newSearchHeading')}</h2>
          <form onSubmit={handleCreateSearch} className="admin-form">
            <div className="admin-form-row">
              <input
                type="text"
                placeholder={t('search.caseReference') ?? ''}
                aria-label={t('search.caseReference') ?? ''}
                value={caseReference}
                onChange={(event) => setCaseReference(event.target.value)}
                required
              />
              <input
                type="text"
                placeholder={t('search.purpose') ?? ''}
                aria-label={t('search.purpose') ?? ''}
                value={purpose}
                onChange={(event) => setPurpose(event.target.value)}
                required
              />
            </div>
            <label className="admin-field-file">
              <span>{t('search.image')}</span>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                onChange={(event) => setImage(event.target.files?.[0] ?? null)}
                required
              />
            </label>
            {isMockProvider && <p className="admin-hint">{t('search.mockNotice')}</p>}
            {formErrorKey && <p className="auth-message auth-message--error">{t(formErrorKey)}</p>}
            <button type="submit" className="admin-submit" disabled={submitting}>
              {submitting ? t('search.searching') : t('search.submit')}
            </button>
          </form>
        </section>
      ) : (
        <section className="admin-panel">
          <p className="admin-hint">{t('search.viewOnlyNotice')}</p>
        </section>
      )}

      {activeSearch && (
        <section className="admin-panel">
          <h2 className="admin-panel__heading">
            {activeSearch.caseReference} · {activeSearch.purpose}
          </h2>
          <p className="admin-hint">{t('search.resultsHint')}</p>
          {activeSearch.latitude !== null && activeSearch.longitude !== null && (
            <p className="admin-hint">
              {t('search.location', {
                lat: formatLatitude(activeSearch.latitude),
                lon: formatLongitude(activeSearch.longitude),
              })}
            </p>
          )}
          {activeSearch.externalEvidenceStatus && (
            <ul className="admin-key-value-list">
              <li>
                <span>{t('search.externalEvidence.web')}</span>
                <span>{t(`osint.status.${activeSearch.externalEvidenceStatus.web}`)}</span>
              </li>
              <li>
                <span>{t('search.externalEvidence.news')}</span>
                <span>{t(`osint.status.${activeSearch.externalEvidenceStatus.news}`)}</span>
              </li>
              <li>
                <span>{t('search.externalEvidence.social')}</span>
                <span>{t(`osint.status.${activeSearch.externalEvidenceStatus.social}`)}</span>
              </li>
              <li>
                <span>{t('search.externalEvidence.reverseImage')}</span>
                <span>{t(`osint.status.${activeSearch.externalEvidenceStatus.reverseImage}`)}</span>
              </li>
            </ul>
          )}

          <SearchExternalEvidence items={activeSearch.externalEvidence} />

          <h3 className="admin-panel__heading">{t('search.subtitle')}</h3>
          <div className="admin-user-list">
            {activeCandidatesLoading && (
              <p className="status-card__line">{t('search.candidatesLoading')}</p>
            )}
            {activeCandidatesError && (
              <p className="status-card__line status-card__line--offline">
                {t('search.candidatesLoadError')}
              </p>
            )}
            {reviewErrorKey && (
              <p className="status-card__line status-card__line--offline">{t(reviewErrorKey)}</p>
            )}
            {!activeCandidatesLoading &&
              !activeCandidatesError &&
              activeCandidates.length === 0 &&
              activeSearch.externalEvidence.length === 0 && (
                <p className="status-card__line">{t('search.noCandidates')}</p>
              )}
            {activeCandidates.map((candidate) => {
              const isBusy = reviewBusyId === candidate.candidateId;
              return (
                <article key={candidate.id} className="admin-user-card">
                  <div className="admin-user-card__row">
                    <div className="admin-user-card__info">
                      <div className="admin-user-card__name">
                        <span>{candidate.referenceCode}</span>
                        <span className="admin-user-card__separator">·</span>
                        <span>{candidate.fullName}</span>
                        <span className="search-score">{(candidate.score * 100).toFixed(1)}%</span>
                        {candidate.status === 'confirmed' && (
                          <span className="admin-badge admin-badge--admin">
                            {t('search.status.confirmed')}
                          </span>
                        )}
                        {candidate.status === 'rejected' && (
                          <span className="admin-badge admin-badge--banned">
                            {t('search.status.rejected')}
                          </span>
                        )}
                        {candidate.status === 'pending' && (
                          <span className="admin-badge admin-badge--pending">
                            {t('search.status.pending')}
                          </span>
                        )}
                        {candidate.status === 'inconclusive' && (
                          <span className="admin-badge admin-badge--pending">
                            {t('search.status.inconclusive')}
                          </span>
                        )}
                        {candidate.status === 'needs_second_review' && (
                          <span className="admin-badge admin-badge--pending">
                            {t('search.status.needsSecondReview')}
                          </span>
                        )}
                      </div>
                      {candidate.reviewedByName && (
                        <p className="admin-user-card__note">
                          {t('search.reviewedBy', { name: candidate.reviewedByName })}
                        </p>
                      )}
                      {evidenceCounts[candidate.candidateId] !== undefined && (
                        <p className="admin-user-card__note">
                          {t('search.evidenceCount', {
                            count: evidenceCounts[candidate.candidateId],
                          })}
                        </p>
                      )}
                      {canSearch && (
                        <button
                          type="button"
                          className="overlay-secondary-button"
                          onClick={() =>
                            setOsintCandidate({ id: candidate.candidateId, name: candidate.fullName })
                          }
                        >
                          {t('osint.openLabel')}
                        </button>
                      )}
                    </div>
                    {canReview &&
                      (candidate.status === 'pending' ||
                        candidate.status === 'inconclusive' ||
                        candidate.status === 'needs_second_review') && (
                        <div className="admin-user-card__actions">
                          <button
                            type="button"
                            className="admin-icon-button admin-icon-button--approve"
                            disabled={isBusy}
                            onClick={() => runReview(candidate.candidateId, 'confirm')}
                          >
                            {t('search.confirmIdentity')}
                          </button>
                          <button
                            type="button"
                            className="admin-icon-button admin-icon-button--reject"
                            disabled={isBusy}
                            onClick={() => runReview(candidate.candidateId, 'reject')}
                          >
                            {t('search.rejectCandidate')}
                          </button>
                          <button
                            type="button"
                            className="admin-icon-button"
                            disabled={isBusy}
                            onClick={() => runReview(candidate.candidateId, 'inconclusive')}
                          >
                            {t('search.markInconclusive')}
                          </button>
                        </div>
                      )}
                  </div>
                </article>
              );
            })}
          </div>
        </section>
      )}

      <section className="admin-user-list">
        <h2 className="admin-panel__heading">{t('search.pastSearches')}</h2>
        {pastSearches === null && !pastSearchesError && (
          <p className="status-card__line">{t('search.loading')}</p>
        )}
        {pastSearchesError && (
          <p className="status-card__line status-card__line--offline">{t('search.loadError')}</p>
        )}
        {pastSearches !== null && pastSearches.length === 0 && (
          <p className="status-card__line">{t('search.empty')}</p>
        )}
        {pastSearches?.map((search) => (
          <article
            key={search.id}
            className="admin-user-card admin-user-card--clickable"
            role="button"
            tabIndex={0}
            onClick={() => openSearch(search)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                openSearch(search);
              }
            }}
          >
            <div className="admin-user-card__row">
              <div className="admin-user-card__info">
                <div className="admin-user-card__name">
                  <span>{search.caseReference}</span>
                  <span className="admin-user-card__separator">·</span>
                  <span>{search.purpose}</span>
                </div>
                <p className="admin-user-card__note">
                  {t('search.requestedBy', { name: search.requestedByName })}
                </p>
              </div>
            </div>
          </article>
        ))}
      </section>

      {osintCandidate && (
        <OsintWorkspace
          candidateId={osintCandidate.id}
          candidateName={osintCandidate.name}
          canManage={canManageCandidates}
          onClose={() => setOsintCandidate(null)}
        />
      )}
    </main>
  );
}
