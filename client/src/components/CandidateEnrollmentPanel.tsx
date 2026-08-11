import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { apiErrorMessageKey } from '../services/apiClient';
import * as candidateClient from '../services/candidateClient';
import type { BiometricTemplate, CandidateRecord, PossibleDuplicate } from '../services/candidateClient';

interface CandidateEnrollmentPanelProps {
  biometricProvider: string | null;
}

export function CandidateEnrollmentPanel({ biometricProvider }: CandidateEnrollmentPanelProps) {
  const { t, i18n } = useTranslation();
  const [referenceCode, setReferenceCode] = useState('');
  const [fullName, setFullName] = useState('');
  const [notes, setNotes] = useState('');
  const [candidate, setCandidate] = useState<CandidateRecord | null>(null);
  const [image, setImage] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [templates, setTemplates] = useState<BiometricTemplate[]>([]);
  const [duplicates, setDuplicates] = useState<PossibleDuplicate[]>([]);
  const [creating, setCreating] = useState(false);
  const [enrolling, setEnrolling] = useState(false);
  const [busyTemplateId, setBusyTemplateId] = useState<string | null>(null);
  const [errorKey, setErrorKey] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    if (!image) {
      setPreviewUrl(null);
      return;
    }
    const url = URL.createObjectURL(image);
    setPreviewUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [image]);

  const refreshTemplates = async (candidateId: string) => {
    setTemplates(await candidateClient.listTemplates(candidateId));
  };

  const handleCreateCandidate = async (event: FormEvent) => {
    event.preventDefault();
    setCreating(true);
    setErrorKey(null);
    setDuplicates([]);
    try {
      const created = await candidateClient.createCandidate(referenceCode.trim(), fullName.trim(), notes.trim());
      setCandidate(created);
      setTemplates([]);
    } catch (error) {
      setErrorKey(apiErrorMessageKey(error, 'candidateEnrollment.createError'));
    } finally {
      setCreating(false);
    }
  };

  const handleEnroll = async (event: FormEvent) => {
    event.preventDefault();
    if (!candidate || !image) return;
    setEnrolling(true);
    setErrorKey(null);
    try {
      const result = await candidateClient.enrollReferencePhoto(candidate.id, image);
      setDuplicates(result.possibleDuplicates);
      await refreshTemplates(candidate.id);
      setImage(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (error) {
      setErrorKey(apiErrorMessageKey(error, 'candidateEnrollment.enrollError'));
    } finally {
      setEnrolling(false);
    }
  };

  const handleRevoke = async (templateId: string) => {
    if (!candidate) return;
    setBusyTemplateId(templateId);
    setErrorKey(null);
    try {
      await candidateClient.revokeTemplate(candidate.id, templateId);
      await refreshTemplates(candidate.id);
    } catch (error) {
      setErrorKey(apiErrorMessageKey(error, 'candidateEnrollment.revokeError'));
    } finally {
      setBusyTemplateId(null);
    }
  };

  const resetCandidate = () => {
    setCandidate(null);
    setReferenceCode('');
    setFullName('');
    setNotes('');
    setImage(null);
    setTemplates([]);
    setDuplicates([]);
    setErrorKey(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const formatDate = (value: string) =>
    new Intl.DateTimeFormat(i18n.resolvedLanguage ?? 'en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));

  return (
    <section className="admin-panel">
      <h2 className="admin-panel__heading">{t('candidateEnrollment.heading')}</h2>
      <p className="admin-hint">{t('candidateEnrollment.hint')}</p>
      {!candidate ? (
        <form className="admin-form" onSubmit={handleCreateCandidate}>
          <div className="admin-form-row">
            <input value={referenceCode} onChange={(event) => setReferenceCode(event.target.value)} placeholder={t('candidateEnrollment.referenceCode') ?? ''} aria-label={t('candidateEnrollment.referenceCode') ?? ''} required />
            <input value={fullName} onChange={(event) => setFullName(event.target.value)} placeholder={t('candidateEnrollment.fullName') ?? ''} aria-label={t('candidateEnrollment.fullName') ?? ''} required />
          </div>
          <textarea value={notes} onChange={(event) => setNotes(event.target.value)} placeholder={t('candidateEnrollment.notes') ?? ''} aria-label={t('candidateEnrollment.notes') ?? ''} />
          {errorKey && <p className="auth-message auth-message--error">{t(errorKey)}</p>}
          <button type="submit" className="admin-submit" disabled={creating}>{creating ? t('candidateEnrollment.creating') : t('candidateEnrollment.create')}</button>
        </form>
      ) : (
        <>
          <article className="admin-user-card">
            <div className="admin-user-card__info">
              <div className="admin-user-card__name"><span>{candidate.referenceCode}</span><span className="admin-user-card__separator">·</span><span>{candidate.fullName}</span></div>
              {candidate.notes && <p className="admin-user-card__note">{candidate.notes}</p>}
            </div>
          </article>
          <form className="admin-form" onSubmit={handleEnroll}>
            <label className="admin-field-file"><span>{t('candidateEnrollment.referencePhoto')}</span><input ref={fileInputRef} type="file" accept="image/jpeg,image/png,image/webp" onChange={(event) => setImage(event.target.files?.[0] ?? null)} required /></label>
            {previewUrl && <img src={previewUrl} alt={t('candidateEnrollment.referencePhoto') ?? ''} style={{ maxWidth: '240px', maxHeight: '240px', objectFit: 'contain' }} />}
            {biometricProvider === 'mock' && <p className="auth-message auth-message--error">{t('candidateEnrollment.mockBlocked')}</p>}
            {errorKey && <p className="auth-message auth-message--error">{t(errorKey)}</p>}
            <div className="admin-form-row">
              <button type="submit" className="admin-submit" disabled={enrolling || biometricProvider === 'mock'}>{enrolling ? t('candidateEnrollment.enrolling') : t('candidateEnrollment.enroll')}</button>
              <button type="button" className="overlay-secondary-button" onClick={resetCandidate}>{t('candidateEnrollment.newCandidate')}</button>
            </div>
          </form>
          {duplicates.length > 0 && (
            <div className="auth-message auth-message--error">
              <strong>{t('candidateEnrollment.duplicatesHeading')}</strong>
              <ul>{duplicates.map((duplicate) => <li key={duplicate.candidateId}>{t('candidateEnrollment.duplicateItem', { candidateId: duplicate.candidateId, score: duplicate.similarity.toFixed(4) })}</li>)}</ul>
              <p>{t('candidateEnrollment.duplicatesHint')}</p>
            </div>
          )}
          <div className="admin-user-list">
            <h3 className="admin-panel__heading">{t('candidateEnrollment.templatesHeading')}</h3>
            {templates.length === 0 && <p className="status-card__line">{t('candidateEnrollment.noTemplates')}</p>}
            {templates.map((template) => (
              <article key={template.id} className="admin-user-card">
                <div className="admin-user-card__row">
                  <div className="admin-user-card__info">
                    <div className="admin-user-card__name"><span>{template.modelName}</span><span className="admin-user-card__separator">·</span><span>{template.modelVersion}</span>{template.revokedAt && <span className="admin-badge admin-badge--banned">{t('candidateEnrollment.revoked')}</span>}</div>
                    <p className="admin-user-card__note">{t('candidateEnrollment.templateMeta', { dimension: template.embeddingDimension, quality: template.qualityScore.toFixed(4), date: formatDate(template.createdAt) })}</p>
                  </div>
                  {!template.revokedAt && <button type="button" className="admin-icon-button admin-icon-button--reject" disabled={busyTemplateId === template.id} onClick={() => handleRevoke(template.id)}>{t('candidateEnrollment.revoke')}</button>}
                </div>
              </article>
            ))}
          </div>
        </>
      )}
    </section>
  );
}
