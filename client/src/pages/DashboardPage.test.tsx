import { render, screen, waitFor } from '@testing-library/react';
import { fireEvent } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { AuthProvider } from '../features/auth/AuthContext';
import i18n from '../i18n/config';
import * as authClient from '../services/authClient';
import * as searchClient from '../services/searchClient';
import type { SearchSummary } from '../services/searchClient';
import { DashboardPage } from './DashboardPage';

const user = {
  id: 'user-1',
  userCode: 'OPERATOR1',
  email: null,
  role: 'OPERATOR',
  firstName: 'A',
  lastName: 'B',
};

const search: SearchSummary = {
  id: 'search-1',
  caseReference: 'CASE-1',
  purpose: 'Test purpose',
  requestedByName: 'A B',
  status: 'completed',
  latitude: null,
  longitude: null,
  topK: 10,
  startedAt: null,
  completedAt: null,
  failureCode: null,
  failureMessageKey: null,
  createdAt: '2026-01-01T00:00:00Z',
  externalEvidenceStatus: null,
  externalEvidence: [],
};

function renderDashboard() {
  return render(
    <AuthProvider>
      <DashboardPage />
    </AuthProvider>,
  );
}

describe('DashboardPage', () => {
  it('shows a load error, not a false "no candidates", when fetching a search\'s candidates fails', async () => {
    vi.spyOn(authClient, 'refresh').mockResolvedValue({ accessToken: 'token', user });
    vi.spyOn(searchClient, 'listSearches').mockResolvedValue({
      items: [search],
      page: 1,
      pageSize: 50,
      total: 1,
    });
    vi.spyOn(searchClient, 'getSearchCandidates').mockRejectedValue(new Error('network error'));
    await i18n.changeLanguage('en');

    renderDashboard();

    const card = await screen.findByText('CASE-1');
    fireEvent.click(card.closest('[role="button"]') as HTMLElement);

    await waitFor(() =>
      expect(screen.getByText('Failed to load candidates for this search.')).toBeInTheDocument(),
    );
    expect(screen.queryByText('No candidates returned.')).not.toBeInTheDocument();
  });
});
