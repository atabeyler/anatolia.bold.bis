import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import App from './App';
import { AuthProvider } from './features/auth/AuthContext';
import i18n, { applyDocumentDirection } from './i18n/config';

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
    expect(screen.getByText('ANATOLIA-BIS')).toBeInTheDocument();
  });

  it('renders the Turkish brand mark with a dotted İ when Turkish is active', async () => {
    await i18n.changeLanguage('tr');
    renderApp();
    expect(screen.getByText('ANATOLİA-BİS')).toBeInTheDocument();
    await i18n.changeLanguage('en');
  });

  it('sets RTL direction on the document when Arabic is selected', () => {
    applyDocumentDirection('ar');
    expect(document.documentElement.dir).toBe('rtl');
    applyDocumentDirection('en');
    expect(document.documentElement.dir).toBe('ltr');
  });
});
