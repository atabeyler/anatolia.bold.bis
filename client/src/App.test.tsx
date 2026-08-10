import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import App from './App';
import { AuthProvider } from './features/auth/AuthContext';
import i18n, { applyDocumentDirection } from './i18n/config';
import * as authClient from './services/authClient';

function renderApp() {
  const queryClient = new QueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe('App', () => {
  it('renders the application brand mark in the active language', async () => {
    await i18n.changeLanguage('en');
    renderApp();
    expect(await screen.findByText('ANATOLIA-BIS')).toBeInTheDocument();
  });

  it('renders the Turkish brand mark with a dotted İ when Turkish is active', async () => {
    await i18n.changeLanguage('tr');
    renderApp();
    expect(await screen.findByText('ANATOLİA-BİS')).toBeInTheDocument();
    await i18n.changeLanguage('en');
  });

  it('sets RTL direction on the document when Arabic is selected', () => {
    applyDocumentDirection('ar');
    expect(document.documentElement.dir).toBe('rtl');
    applyDocumentDirection('en');
    expect(document.documentElement.dir).toBe('ltr');
  });

  it('falls back to the sign-in screen when the session cannot be restored (session expiry)', async () => {
    await i18n.changeLanguage('en');
    vi.spyOn(authClient, 'refresh').mockRejectedValue(new Error('refresh token expired'));
    renderApp();
    expect((await screen.findAllByText('Sign in')).length).toBeGreaterThan(0);
  });

  it('does not show the management panel button to a non-admin role', async () => {
    await i18n.changeLanguage('en');
    vi.spyOn(authClient, 'refresh').mockResolvedValue({
      accessToken: 'token',
      user: { id: 'u1', userCode: 'reviewer1', email: null, role: 'REVIEWER', firstName: 'R', lastName: 'V' },
    });
    renderApp();
    await waitFor(() => expect(screen.queryByLabelText('Management panel')).not.toBeInTheDocument());
  });

  it('shows the management panel button to a SYSTEM_ADMIN role', async () => {
    await i18n.changeLanguage('en');
    vi.spyOn(authClient, 'refresh').mockResolvedValue({
      accessToken: 'token',
      user: { id: 'u2', userCode: 'admin1', email: null, role: 'SYSTEM_ADMIN', firstName: 'S', lastName: 'A' },
    });
    renderApp();
    expect(await screen.findByLabelText('Management panel')).toBeInTheDocument();
  });
});
