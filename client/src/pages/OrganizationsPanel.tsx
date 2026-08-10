import { useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import * as orgClient from '../services/orgClient';
import type { Organization, OrganizationUnit } from '../services/orgClient';
import { apiErrorMessageKey } from '../services/apiClient';

export function OrganizationsPanel() {
  const { t } = useTranslation();
  const [organizations, setOrganizations] = useState<Organization[] | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [orgName, setOrgName] = useState('');
  const [creatingOrg, setCreatingOrg] = useState(false);
  const [orgMessage, setOrgMessage] = useState<string | null>(null);

  const [selectedOrgId, setSelectedOrgId] = useState<string | null>(null);
  const [units, setUnits] = useState<OrganizationUnit[] | null>(null);
  const [unitName, setUnitName] = useState('');
  const [creatingUnit, setCreatingUnit] = useState(false);

  const [membershipUserId, setMembershipUserId] = useState('');
  const [membershipOrgId, setMembershipOrgId] = useState('');
  const [membershipMessage, setMembershipMessage] = useState<string | null>(null);
  const [assigning, setAssigning] = useState(false);

  const loadOrganizations = () => {
    setLoadError(false);
    orgClient
      .listOrganizations()
      .then(setOrganizations)
      .catch(() => setLoadError(true));
  };

  useEffect(() => {
    loadOrganizations();
  }, []);

  useEffect(() => {
    if (!selectedOrgId) {
      setUnits(null);
      return;
    }
    orgClient
      .listUnits(selectedOrgId)
      .then(setUnits)
      .catch(() => setUnits([]));
  }, [selectedOrgId]);

  const handleCreateOrg = async (event: FormEvent) => {
    event.preventDefault();
    setOrgMessage(null);
    setCreatingOrg(true);
    try {
      await orgClient.createOrganization(orgName.trim());
      setOrgName('');
      loadOrganizations();
    } catch (error) {
      setOrgMessage(t(apiErrorMessageKey(error, 'errors.internal')) ?? '');
    } finally {
      setCreatingOrg(false);
    }
  };

  const handleCreateUnit = async (event: FormEvent) => {
    event.preventDefault();
    if (!selectedOrgId) return;
    setCreatingUnit(true);
    try {
      await orgClient.createUnit(selectedOrgId, unitName.trim());
      setUnitName('');
      const refreshed = await orgClient.listUnits(selectedOrgId);
      setUnits(refreshed);
    } catch {
      // Surfaced implicitly: the unit list simply doesn't grow.
    } finally {
      setCreatingUnit(false);
    }
  };

  const handleAssignMembership = async (event: FormEvent) => {
    event.preventDefault();
    setMembershipMessage(null);
    setAssigning(true);
    try {
      await orgClient.assignMembership(membershipUserId.trim(), membershipOrgId.trim());
      setMembershipMessage(t('admin.org.membershipAssigned') ?? '');
      setMembershipUserId('');
    } catch (error) {
      setMembershipMessage(t(apiErrorMessageKey(error, 'errors.internal')) ?? '');
    } finally {
      setAssigning(false);
    }
  };

  return (
    <>
      <section className="admin-panel">
        <h2 className="admin-panel__heading">{t('admin.org.createHeading')}</h2>
        <form onSubmit={handleCreateOrg} className="admin-form">
          <div className="admin-form-row">
            <input
              type="text"
              placeholder={t('admin.org.namePlaceholder') ?? ''}
              aria-label={t('admin.org.namePlaceholder') ?? ''}
              value={orgName}
              onChange={(event) => setOrgName(event.target.value)}
              required
            />
          </div>
          {orgMessage && <p className="auth-message auth-message--error">{orgMessage}</p>}
          <button type="submit" className="admin-submit" disabled={creatingOrg}>
            {t('admin.org.createSubmit')}
          </button>
        </form>
      </section>

      <section className="admin-user-list">
        {organizations === null && !loadError && <p className="status-card__line">{t('admin.loading')}</p>}
        {loadError && <p className="status-card__line status-card__line--offline">{t('admin.loadError')}</p>}
        {organizations !== null && organizations.length === 0 && (
          <p className="status-card__line">{t('admin.org.empty')}</p>
        )}
        {organizations?.map((org) => (
          <article key={org.id} className="admin-user-card">
            <div className="admin-user-card__row">
              <div className="admin-user-card__info">
                <div className="admin-user-card__name">
                  <span>{org.name}</span>
                </div>
              </div>
              <div className="admin-user-card__actions">
                <button
                  type="button"
                  className="admin-icon-button"
                  onClick={() => setSelectedOrgId(selectedOrgId === org.id ? null : org.id)}
                >
                  {t('admin.org.units')}
                </button>
              </div>
            </div>
            {selectedOrgId === org.id && (
              <div className="admin-edit-form">
                <ul>
                  {units?.map((unit) => (
                    <li key={unit.id}>{unit.name}</li>
                  ))}
                  {units !== null && units?.length === 0 && (
                    <li className="admin-hint">{t('admin.org.noUnits')}</li>
                  )}
                </ul>
                <form onSubmit={handleCreateUnit} className="admin-form-row">
                  <input
                    type="text"
                    placeholder={t('admin.org.unitNamePlaceholder') ?? ''}
                    aria-label={t('admin.org.unitNamePlaceholder') ?? ''}
                    value={unitName}
                    onChange={(event) => setUnitName(event.target.value)}
                    required
                  />
                  <button type="submit" className="admin-submit" disabled={creatingUnit}>
                    {t('admin.org.addUnit')}
                  </button>
                </form>
              </div>
            )}
          </article>
        ))}
      </section>

      <section className="admin-panel">
        <h2 className="admin-panel__heading">{t('admin.org.membershipHeading')}</h2>
        <p className="admin-hint">{t('admin.org.membershipHint')}</p>
        <form onSubmit={handleAssignMembership} className="admin-form">
          <div className="admin-form-row">
            <input
              type="text"
              placeholder={t('admin.org.userIdPlaceholder') ?? ''}
              aria-label={t('admin.org.userIdPlaceholder') ?? ''}
              value={membershipUserId}
              onChange={(event) => setMembershipUserId(event.target.value)}
              required
            />
            <input
              type="text"
              placeholder={t('admin.org.organizationIdPlaceholder') ?? ''}
              aria-label={t('admin.org.organizationIdPlaceholder') ?? ''}
              value={membershipOrgId}
              onChange={(event) => setMembershipOrgId(event.target.value)}
              required
            />
          </div>
          {membershipMessage && <p className="auth-message auth-message--success">{membershipMessage}</p>}
          <button type="submit" className="admin-submit" disabled={assigning}>
            {t('admin.org.assignSubmit')}
          </button>
        </form>
      </section>
    </>
  );
}
