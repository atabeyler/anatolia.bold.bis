import { useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import * as adminClient from '../services/adminClient';
import type { AdminUser } from '../services/adminClient';
import { apiErrorMessageKey } from '../services/apiClient';
import { OrganizationsPanel } from './OrganizationsPanel';
import { SystemPanel } from './SystemPanel';

const NATIONAL_ID_PATTERN = /^[0-9]{11}$/;

interface EditForm {
  nickname: string;
  nationalId: string;
  // The backend now returns a masked national ID (see
  // permission::mask_national_id) — the input is pre-filled with that
  // masked value purely for display, so submitting it unchanged must
  // never overwrite the real stored value with masked characters. Only
  // an explicit edit sets this and is included in the update payload.
  nationalIdTouched: boolean;
  email: string;
  password: string;
}

const EMPTY_EDIT_FORM: EditForm = {
  nickname: '',
  nationalId: '',
  nationalIdTouched: false,
  email: '',
  password: '',
};

const PAGE_SIZE = 50;

type AdminTab = 'users' | 'organizations' | 'system';

export function AdminPage() {
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState<AdminTab>('users');
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loadError, setLoadError] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [userCode, setUserCode] = useState('');
  const [password, setPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [nationalId, setNationalId] = useState('');
  const [email, setEmail] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [formMessage, setFormMessage] = useState<{
    type: 'error' | 'success';
    key: string;
  } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<EditForm>(EMPTY_EDIT_FORM);
  const [editMessage, setEditMessage] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const loadUsers = (targetPage = page) => {
    setLoadError(false);
    adminClient
      .listUsers(targetPage, PAGE_SIZE)
      .then((result) => {
        setUsers(result.items);
        setTotal(result.total);
        setPage(result.page);
      })
      .catch(() => setLoadError(true));
  };

  useEffect(() => {
    loadUsers(1);
    // Only re-fetches the first page automatically on mount; `loadUsers`
    // is called explicitly with the current page after any action
    // (create/edit/ban/delete) so the list stays in sync without needing
    // `page` as an effect dependency here.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const runAction = async (id: string, action: () => Promise<void>) => {
    setBusyId(id);
    setActionError(null);
    try {
      await action();
      loadUsers();
    } catch (error) {
      setActionError(t(apiErrorMessageKey(error, 'errors.internal')) ?? '');
    } finally {
      setBusyId(null);
    }
  };

  const handleCreate = async (event: FormEvent) => {
    event.preventDefault();
    setFormMessage(null);
    setSubmitting(true);
    try {
      await adminClient.createUser({
        userCode: userCode.trim(),
        password,
        firstName: firstName.trim() || undefined,
        lastName: lastName.trim() || undefined,
        nationalId: nationalId.trim(),
        email: email.trim(),
        isAdmin,
      });
      setUserCode('');
      setPassword('');
      setFirstName('');
      setLastName('');
      setNationalId('');
      setEmail('');
      setIsAdmin(false);
      setFormMessage({ type: 'success', key: 'admin.createSuccess' });
      loadUsers();
    } catch (error) {
      setFormMessage({
        type: 'error',
        key: apiErrorMessageKey(error, 'admin.createError'),
      });
    } finally {
      setSubmitting(false);
    }
  };

  const startEdit = (user: AdminUser) => {
    setEditingId(user.id);
    setEditMessage(null);
    setEditForm({
      nickname: user.firstName,
      nationalId: user.nationalId ?? '',
      nationalIdTouched: false,
      email: user.email ?? '',
      password: '',
    });
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditForm(EMPTY_EDIT_FORM);
    setEditMessage(null);
  };

  const submitEdit = async (event: FormEvent, id: string) => {
    event.preventDefault();
    setBusyId(id);
    setEditMessage(null);
    try {
      await adminClient.updateUser(id, {
        nickname: editForm.nickname.trim() || undefined,
        nationalId: editForm.nationalIdTouched ? editForm.nationalId.trim() || undefined : undefined,
        email: editForm.email.trim() || undefined,
        password: editForm.password || undefined,
      });
      setEditingId(null);
      setEditForm(EMPTY_EDIT_FORM);
      loadUsers();
    } catch (error) {
      setEditMessage(t(apiErrorMessageKey(error, 'admin.createError')) ?? '');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <main className="admin-page">
      <nav className="admin-tabs">
        <button
          type="button"
          className={`admin-tabs__tab ${activeTab === 'users' ? 'admin-tabs__tab--active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          {t('admin.tabUsers')}
        </button>
        <button
          type="button"
          className={`admin-tabs__tab ${activeTab === 'organizations' ? 'admin-tabs__tab--active' : ''}`}
          onClick={() => setActiveTab('organizations')}
        >
          {t('admin.tabOrganizations')}
        </button>
        <button
          type="button"
          className={`admin-tabs__tab ${activeTab === 'system' ? 'admin-tabs__tab--active' : ''}`}
          onClick={() => setActiveTab('system')}
        >
          {t('admin.tabSystem')}
        </button>
      </nav>

      {activeTab === 'organizations' && <OrganizationsPanel />}
      {activeTab === 'system' && <SystemPanel />}

      {activeTab === 'users' && (
        <>
          <section className="admin-panel">
            <h2 className="admin-panel__heading">{t('admin.addUser.heading')}</h2>
            <form onSubmit={handleCreate} className="admin-form">
              <div className="admin-form-row">
                <input
                  type="text"
                  placeholder={t('admin.addUser.userCode') ?? ''}
                  aria-label={t('admin.addUser.userCode') ?? ''}
                  value={userCode}
                  onChange={(event) => setUserCode(event.target.value)}
                  required
                />
                <div className="admin-name-stack">
                  <input
                    type="text"
                    placeholder={t('auth.firstName') ?? ''}
                    aria-label={t('auth.firstName') ?? ''}
                    value={firstName}
                    onChange={(event) => setFirstName(event.target.value)}
                  />
                  <input
                    type="text"
                    placeholder={t('auth.lastName') ?? ''}
                    aria-label={t('auth.lastName') ?? ''}
                    value={lastName}
                    onChange={(event) => setLastName(event.target.value)}
                  />
                </div>
              </div>
              <div className="admin-form-row">
                <input
                  type="password"
                  placeholder={t('admin.addUser.password') ?? ''}
                  aria-label={t('admin.addUser.password') ?? ''}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  minLength={8}
                  required
                />
                <input
                  type="text"
                  placeholder={t('admin.addUser.nationalId') ?? ''}
                  aria-label={t('admin.addUser.nationalId') ?? ''}
                  value={nationalId}
                  onChange={(event) => setNationalId(event.target.value.replace(/[^0-9]/g, ''))}
                  maxLength={11}
                  pattern={NATIONAL_ID_PATTERN.source}
                  required
                />
              </div>
              <div className="admin-form-row">
                <input
                  type="email"
                  placeholder={t('admin.addUser.email') ?? ''}
                  aria-label={t('admin.addUser.email') ?? ''}
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  required
                />
              </div>
              <label className="admin-checkbox-row">
                <input
                  type="checkbox"
                  checked={isAdmin}
                  onChange={(event) => setIsAdmin(event.target.checked)}
                />
                {t('admin.addUser.isAdmin')}
              </label>
              <p className="admin-hint">{t('admin.addUser.hint')}</p>
              {formMessage && (
                <p
                  className={`auth-message auth-message--${formMessage.type === 'success' ? 'success' : 'error'}`}
                >
                  {t(formMessage.key)}
                </p>
              )}
              <button type="submit" className="admin-submit" disabled={submitting}>
                {t('admin.addUser.submit')}
              </button>
            </form>
          </section>

          <section className="admin-user-list">
            {actionError && <p className="status-card__line status-card__line--offline">{actionError}</p>}
            {users === null && !loadError && <p className="status-card__line">{t('admin.loading')}</p>}
            {loadError && (
              <p className="status-card__line status-card__line--offline">{t('admin.loadError')}</p>
            )}
            {users !== null && users.length === 0 && <p className="status-card__line">{t('admin.empty')}</p>}
            {users?.map((user) => {
              const isBusy = busyId === user.id;
              const isPending = !user.isApproved;
              const isEditing = editingId === user.id;
              return (
                <article key={user.id} className="admin-user-card">
                  <div className="admin-user-card__row">
                    <div className="admin-user-card__info">
                      <div className="admin-user-card__name">
                        <span>{user.userCode}</span>
                        {(user.firstName || user.lastName) && (
                          <>
                            <span className="admin-user-card__separator">·</span>
                            <span>{[user.firstName, user.lastName].filter(Boolean).join(' ')}</span>
                          </>
                        )}
                        {(user.role === 'SYSTEM_ADMIN' || user.role === 'SECURITY_ADMIN') && (
                          <span className="admin-badge admin-badge--admin">{t('admin.badge.admin')}</span>
                        )}
                        {isPending && !user.isBanned && (
                          <span className="admin-badge admin-badge--pending">{t('admin.badge.pending')}</span>
                        )}
                        {user.isBanned && (
                          <span className="admin-badge admin-badge--banned">{t('admin.badge.banned')}</span>
                        )}
                      </div>
                      {!user.email && <p className="admin-user-card__note">{t('admin.noEmail')}</p>}
                    </div>
                    <div className="admin-user-card__actions">
                      <label className="admin-role-select">
                        <span className="sr-only">{t('admin.roleLabel')}</span>
                        <select
                          value={user.role}
                          disabled={isBusy || isPending}
                          onChange={(event) => {
                            const role = event.target.value;
                            if (role === user.role) return;
                            if (window.confirm(t('admin.confirmRoleChange') ?? '')) {
                              runAction(user.id, () => adminClient.changeRole(user.id, role));
                            }
                          }}
                        >
                          {adminClient.ASSIGNABLE_ROLES.map((role) => (
                            <option key={role} value={role}>
                              {t(`admin.roles.${role}`)}
                            </option>
                          ))}
                        </select>
                      </label>
                      {isPending && !user.isBanned && (
                        <>
                          <button
                            type="button"
                            className="admin-icon-button admin-icon-button--approve"
                            disabled={isBusy}
                            onClick={() => runAction(user.id, () => adminClient.approveUser(user.id))}
                          >
                            {t('admin.actions.approve')}
                          </button>
                          <button
                            type="button"
                            className="admin-icon-button admin-icon-button--reject"
                            disabled={isBusy}
                            onClick={() => runAction(user.id, () => adminClient.rejectUser(user.id))}
                          >
                            {t('admin.actions.reject')}
                          </button>
                        </>
                      )}
                      {!isPending && !user.isBanned && (
                        <button
                          type="button"
                          className="admin-icon-button admin-icon-button--ban"
                          disabled={isBusy}
                          onClick={() => {
                            if (window.confirm(t('admin.confirmBan') ?? '')) {
                              runAction(user.id, () => adminClient.banUser(user.id));
                            }
                          }}
                        >
                          {t('admin.actions.ban')}
                        </button>
                      )}
                      {user.isBanned && (
                        <button
                          type="button"
                          className="admin-icon-button admin-icon-button--unban"
                          disabled={isBusy}
                          onClick={() => runAction(user.id, () => adminClient.unbanUser(user.id))}
                        >
                          {t('admin.actions.unban')}
                        </button>
                      )}
                      <button
                        type="button"
                        className="admin-icon-button admin-icon-button--edit"
                        disabled={isBusy}
                        onClick={() => (isEditing ? cancelEdit() : startEdit(user))}
                      >
                        {t('admin.actions.edit')}
                      </button>
                      <button
                        type="button"
                        className="admin-icon-button admin-icon-button--delete"
                        disabled={isBusy}
                        onClick={() => {
                          if (window.confirm(t('admin.confirmDelete') ?? '')) {
                            runAction(user.id, () => adminClient.deleteUser(user.id));
                          }
                        }}
                      >
                        {t('admin.actions.delete')}
                      </button>
                    </div>
                  </div>

                  {isEditing && (
                    <form className="admin-edit-form" onSubmit={(event) => submitEdit(event, user.id)}>
                      <div className="admin-form-row">
                        <input
                          type="text"
                          placeholder={t('admin.addUser.nickname') ?? ''}
                          aria-label={t('admin.addUser.nickname') ?? ''}
                          value={editForm.nickname}
                          onChange={(event) =>
                            setEditForm((form) => ({
                              ...form,
                              nickname: event.target.value,
                            }))
                          }
                        />
                        <input
                          type="text"
                          placeholder={t('admin.addUser.nationalId') ?? ''}
                          aria-label={t('admin.addUser.nationalId') ?? ''}
                          value={editForm.nationalId}
                          onChange={(event) =>
                            setEditForm((form) => ({
                              ...form,
                              nationalId: event.target.value.replace(/[^0-9]/g, ''),
                              nationalIdTouched: true,
                            }))
                          }
                          maxLength={11}
                        />
                      </div>
                      <div className="admin-form-row">
                        <input
                          type="email"
                          placeholder={t('admin.addUser.email') ?? ''}
                          aria-label={t('admin.addUser.email') ?? ''}
                          value={editForm.email}
                          onChange={(event) =>
                            setEditForm((form) => ({
                              ...form,
                              email: event.target.value,
                            }))
                          }
                        />
                        <input
                          type="password"
                          placeholder={t('admin.actions.newPassword') ?? ''}
                          aria-label={t('admin.actions.newPassword') ?? ''}
                          value={editForm.password}
                          onChange={(event) =>
                            setEditForm((form) => ({
                              ...form,
                              password: event.target.value,
                            }))
                          }
                          minLength={8}
                        />
                      </div>
                      {editMessage && <p className="auth-message auth-message--error">{editMessage}</p>}
                      <div className="admin-edit-form__actions">
                        <button type="submit" className="admin-submit" disabled={isBusy}>
                          {t('admin.actions.save')}
                        </button>
                        <button type="button" className="admin-icon-button" onClick={cancelEdit}>
                          {t('admin.actions.cancel')}
                        </button>
                      </div>
                    </form>
                  )}
                </article>
              );
            })}
            {users !== null && users.length > 0 && (
              <nav className="admin-pagination">
                <button
                  type="button"
                  className="admin-icon-button"
                  disabled={page <= 1}
                  onClick={() => loadUsers(page - 1)}
                >
                  {t('admin.pagination.previous')}
                </button>
                <span className="status-card__line">
                  {t('admin.pagination.pageOf', { page, totalPages })}
                </span>
                <button
                  type="button"
                  className="admin-icon-button"
                  disabled={page >= totalPages}
                  onClick={() => loadUsers(page + 1)}
                >
                  {t('admin.pagination.next')}
                </button>
              </nav>
            )}
          </section>
        </>
      )}
    </main>
  );
}
