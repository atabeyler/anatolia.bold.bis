import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import * as auditClient from '../services/auditClient';
import type { AuditEvent, AuditEventFilters } from '../services/auditClient';

const PAGE_SIZE = 50;

const EMPTY_FILTERS: AuditEventFilters = {};

export function AuditPage() {
  const { t, i18n } = useTranslation();
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState<'idle' | 'loading' | 'error'>('idle');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const [draftFilters, setDraftFilters] = useState<AuditEventFilters>(EMPTY_FILTERS);
  const [appliedFilters, setAppliedFilters] = useState<AuditEventFilters>(EMPTY_FILTERS);

  const load = useCallback((filters: AuditEventFilters, targetPage: number) => {
    setStatus('loading');
    auditClient
      .listAuditEvents({ ...filters, page: targetPage, pageSize: PAGE_SIZE })
      .then((result) => {
        setEvents(result.items);
        setTotal(result.total);
        setPage(result.page);
        setStatus('idle');
      })
      .catch(() => setStatus('error'));
  }, []);

  useEffect(() => {
    load(appliedFilters, 1);
  }, [appliedFilters, load]);

  const handleFilterSubmit = (event: FormEvent) => {
    event.preventDefault();
    setAppliedFilters(draftFilters);
  };

  const clearFilters = () => {
    setDraftFilters(EMPTY_FILTERS);
    setAppliedFilters(EMPTY_FILTERS);
  };

  const dateFormatter = new Intl.DateTimeFormat(i18n.resolvedLanguage, {
    dateStyle: 'short',
    timeStyle: 'medium',
  });

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <main className="admin-page">
      <nav className="admin-tabs">
        <span className="admin-tabs__tab admin-tabs__tab--active">{t('audit.tabTitle')}</span>
      </nav>

      <section className="admin-panel">
        <h2 className="admin-panel__heading">{t('audit.filters.heading')}</h2>
        <form className="admin-form" onSubmit={handleFilterSubmit}>
          <div className="admin-form-row">
            <label className="auth-field">
              <span>{t('audit.filters.dateFrom')}</span>
              <input
                type="datetime-local"
                value={draftFilters.dateFrom ?? ''}
                onChange={(event) =>
                  setDraftFilters((f) => ({
                    ...f,
                    dateFrom: event.target.value || undefined,
                  }))
                }
              />
            </label>
            <label className="auth-field">
              <span>{t('audit.filters.dateTo')}</span>
              <input
                type="datetime-local"
                value={draftFilters.dateTo ?? ''}
                onChange={(event) =>
                  setDraftFilters((f) => ({
                    ...f,
                    dateTo: event.target.value || undefined,
                  }))
                }
              />
            </label>
          </div>
          <div className="admin-form-row">
            <input
              type="text"
              placeholder={t('audit.filters.action') ?? ''}
              aria-label={t('audit.filters.action') ?? ''}
              value={draftFilters.action ?? ''}
              onChange={(event) =>
                setDraftFilters((f) => ({
                  ...f,
                  action: event.target.value || undefined,
                }))
              }
            />
            <input
              type="text"
              placeholder={t('audit.filters.result') ?? ''}
              aria-label={t('audit.filters.result') ?? ''}
              value={draftFilters.result ?? ''}
              onChange={(event) =>
                setDraftFilters((f) => ({
                  ...f,
                  result: event.target.value || undefined,
                }))
              }
            />
          </div>
          <div className="admin-form-row">
            <input
              type="text"
              placeholder={t('audit.filters.caseReference') ?? ''}
              aria-label={t('audit.filters.caseReference') ?? ''}
              value={draftFilters.caseReference ?? ''}
              onChange={(event) =>
                setDraftFilters((f) => ({
                  ...f,
                  caseReference: event.target.value || undefined,
                }))
              }
            />
            <input
              type="text"
              placeholder={t('audit.filters.resourceType') ?? ''}
              aria-label={t('audit.filters.resourceType') ?? ''}
              value={draftFilters.resourceType ?? ''}
              onChange={(event) =>
                setDraftFilters((f) => ({
                  ...f,
                  resourceType: event.target.value || undefined,
                }))
              }
            />
          </div>
          <p className="admin-hint">{t('audit.filters.hint')}</p>
          <div className="admin-edit-form__actions">
            <button type="submit" className="admin-submit">
              {t('audit.filters.apply')}
            </button>
            <button type="button" className="admin-icon-button" onClick={clearFilters}>
              {t('audit.filters.clear')}
            </button>
          </div>
        </form>
      </section>

      <section className="admin-user-list">
        {status === 'loading' && <p className="status-card__line">{t('audit.loading')}</p>}
        {status === 'error' && (
          <p className="status-card__line status-card__line--offline">{t('audit.loadError')}</p>
        )}
        {status === 'idle' && events !== null && events.length === 0 && (
          <p className="status-card__line">{t('audit.empty')}</p>
        )}

        {status === 'idle' &&
          events?.map((event) => {
            const isExpanded = expandedId === event.id;
            return (
              <article key={event.id} className="admin-user-card">
                <div className="admin-user-card__row">
                  <div className="admin-user-card__info">
                    <div className="admin-user-card__name">
                      <span>{dateFormatter.format(new Date(event.timestamp))}</span>
                      <span className="admin-user-card__separator">·</span>
                      <span>{event.action}</span>
                      <span
                        className={
                          event.result === 'success'
                            ? 'admin-badge admin-badge--admin'
                            : event.result === 'denied'
                              ? 'admin-badge admin-badge--pending'
                              : 'admin-badge admin-badge--banned'
                        }
                      >
                        {event.result}
                      </span>
                    </div>
                    <p className="admin-user-card__note">
                      {event.actorUserCode ?? t('audit.unknownActor')}
                      {event.actorRole ? ` (${event.actorRole})` : ''}
                      {event.caseReference
                        ? ` · ${t('audit.filters.caseReference')}: ${event.caseReference}`
                        : ''}
                      {event.resourceType
                        ? ` · ${event.resourceType}${event.resourceId ? `#${event.resourceId.slice(0, 8)}` : ''}`
                        : ''}
                    </p>
                  </div>
                  <div className="admin-user-card__actions">
                    <button
                      type="button"
                      className="admin-icon-button"
                      onClick={() => setExpandedId(isExpanded ? null : event.id)}
                    >
                      {isExpanded ? t('audit.hideDetail') : t('audit.showDetail')}
                    </button>
                  </div>
                </div>

                {isExpanded && (
                  <dl className="audit-detail">
                    <dt>{t('audit.detail.requestId')}</dt>
                    <dd>{event.requestId}</dd>
                    <dt>{t('audit.detail.ipAddress')}</dt>
                    <dd>{event.ipAddress ?? '—'}</dd>
                    <dt>{t('audit.detail.userAgent')}</dt>
                    <dd>{event.userAgent ?? '—'}</dd>
                    <dt>{t('audit.detail.metadata')}</dt>
                    <dd>
                      <pre className="audit-detail__metadata">
                        {event.metadata ? JSON.stringify(event.metadata, null, 2) : '—'}
                      </pre>
                    </dd>
                  </dl>
                )}
              </article>
            );
          })}
      </section>

      {status === 'idle' && total > 0 && (
        <nav className="admin-pagination">
          <button
            type="button"
            className="admin-icon-button"
            disabled={page <= 1}
            onClick={() => load(appliedFilters, page - 1)}
          >
            {t('audit.pagination.previous')}
          </button>
          <span className="status-card__line">{t('audit.pagination.pageOf', { page, totalPages })}</span>
          <button
            type="button"
            className="admin-icon-button"
            disabled={page >= totalPages}
            onClick={() => load(appliedFilters, page + 1)}
          >
            {t('audit.pagination.next')}
          </button>
        </nav>
      )}
    </main>
  );
}
