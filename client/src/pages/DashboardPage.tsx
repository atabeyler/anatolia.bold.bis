import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { Logo } from '../components/Logo';
import { useAuth } from '../features/auth/AuthContext';
import { formatLatitude, formatLongitude, getLastKnownLocation } from '../hooks/useGeolocation';
import { brandMark } from '../lib/brand';
import * as searchClient from '../services/searchClient';
import type { SearchCandidate, SearchSummary } from '../services/searchClient';
import { apiErrorMessageKey } from '../services/apiClient';

const ADMIN_ROLES = ['SYSTEM_ADMIN', 'SECURITY_ADMIN'];
const REVIEW_ROLES = ['REVIEWER', 'SECURITY_ADMIN', 'SYSTEM_ADMIN'];

interface DashboardPageProps {
  onOpenAdmin?: () => void;
}

export function DashboardPage({ onOpenAdmin }: DashboardPageProps) {
  const { t, i18n } = useTranslation();
  const { user, logout } = useAuth();
  const isAdmin = !!user && ADMIN_ROLES.includes(user.role);
  const canReview = !!user && REVIEW_ROLES.includes(user.role);

  const [caseReference, setCaseReference] = useState('');
  const [purpose, setPurpose] = useState('');
  const [image, setImage] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [formErrorKey, setFormErrorKey] = useState<string | null>(null);

  const [activeSearch, setActiveSearch] = useState<SearchSummary | null>(null);
  const [activeCandidates, setActiveCandidates] = useState<SearchCandidate[]>([]);
  const [reviewBusyId, setReviewBusyId] = useState<string | null>(null);

  const [pastSearches, setPastSearches] = useState<SearchSummary[] | null>(null);
  const [pastSearchesError, setPastSearchesError] = useState(false);

  const loadPastSearches = () => {
    setPastSearchesError(false);
    searchClient
      .listSearches()
      .then(setPastSearches)
      .catch(() => setPastSearchesError(true));
  };

  useEffect(() => {
    loadPastSearches();
  }, []);

  const openSearch = async (search: SearchSummary) => {
    setActiveSearch(search);
    setActiveCandidates(await searchClient.getSearchCandidates(search.id).catch(() => []));
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
      const result = await searchClient.createSearch(caseReference.trim(), purpose.trim(), image, getLastKnownLocation());
      setActiveSearch(result.search);
      setActiveCandidates(result.candidates);
      setCaseReference('');
      setPurpose('');
      setImage(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
      loadPastSearches();
    } catch (error) {
      setFormErrorKey(apiErrorMessageKey(error, 'search.createError'));
    } finally {
      setSubmitting(false);
    }
  };

  const runReview = async (candidateId: string, action: 'confirm' | 'reject') => {
    if (!activeSearch) return;
    setReviewBusyId(candidateId);
    try {
      const updated =
        action === 'confirm'
          ? await searchClient.verifyCandidate(candidateId, activeSearch.id)
          : await searchClient.rejectCandidate(candidateId, activeSearch.id);
      setActiveCandidates((rows) => rows.map((row) => (row.candidateId === candidateId ? updated : row)));
    } finally {
      setReviewBusyId(null);
    }
  };

  return (
    <main className="admin-page">
      <header className="admin-header">
        <div className="admin-header__brand">
          <Logo />
          <div>
            <div className="admin-header__title">{brandMark(i18n.resolvedLanguage)}</div>
            <div className="admin-header__subtitle">{t('search.subtitle')}</div>
          </div>
        </div>
        {user && (
          <div className="app-header__session">
            <span>{t('auth.welcomeBack', { name: `${user.firstName} ${user.lastName}` })}</span>
            {isAdmin && onOpenAdmin && (
              <button type="button" onClick={onOpenAdmin}>
                {t('admin.openLabel')}
              </button>
            )}
            <button type="button" onClick={() => void logout()}>
              {t('auth.logout')}
            </button>
          </div>
        )}
      </header>

      <nav className="admin-tabs">
        <span className="admin-tabs__tab admin-tabs__tab--active">{t('search.tabSearch')}</span>
      </nav>

      <section className="admin-panel">
        <h2 className="admin-panel__heading">{t('search.newSearchHeading')}</h2>
        <form onSubmit={handleCreateSearch} className="admin-form">
          <div className="admin-form-row">
            <input
              type="text"
              placeholder={t('search.caseReference') ?? ''}
              value={caseReference}
              onChange={(event) => setCaseReference(event.target.value)}
              required
            />
            <input
              type="text"
              placeholder={t('search.purpose') ?? ''}
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
              capture="user"
              onChange={(event) => setImage(event.target.files?.[0] ?? null)}
              required
            />
          </label>
          {formErrorKey && <p className="auth-message auth-message--error">{t(formErrorKey)}</p>}
          <button type="submit" className="admin-submit" disabled={submitting}>
            {submitting ? t('search.searching') : t('search.submit')}
          </button>
        </form>
      </section>

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
          <div className="admin-user-list">
            {activeCandidates.length === 0 && <p className="status-card__line">{t('search.noCandidates')}</p>}
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
                          <span className="admin-badge admin-badge--admin">{t('search.status.confirmed')}</span>
                        )}
                        {candidate.status === 'rejected' && (
                          <span className="admin-badge admin-badge--banned">{t('search.status.rejected')}</span>
                        )}
                        {candidate.status === 'pending' && (
                          <span className="admin-badge admin-badge--pending">{t('search.status.pending')}</span>
                        )}
                      </div>
                      {candidate.reviewedByName && (
                        <p className="admin-user-card__note">
                          {t('search.reviewedBy', { name: candidate.reviewedByName })}
                        </p>
                      )}
                    </div>
                    {canReview && candidate.status === 'pending' && (
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
        {pastSearches === null && !pastSearchesError && <p className="status-card__line">{t('search.loading')}</p>}
        {pastSearchesError && <p className="status-card__line status-card__line--offline">{t('search.loadError')}</p>}
        {pastSearches !== null && pastSearches.length === 0 && <p className="status-card__line">{t('search.empty')}</p>}
        {pastSearches?.map((search) => (
          <article key={search.id} className="admin-user-card admin-user-card--clickable" onClick={() => openSearch(search)}>
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
    </main>
  );
}
