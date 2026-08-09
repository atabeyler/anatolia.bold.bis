import { act, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { AuthProvider, useAuth } from './AuthContext';
import * as authClient from '../../services/authClient';

const user = {
  id: 'user-1',
  userCode: 'operator1',
  email: null,
  role: 'OPERATOR',
  firstName: 'A',
  lastName: 'B',
};

function Probe({ testId }: { testId: string }) {
  const { status, login, logout } = useAuth();
  return (
    <div>
      <span data-testid={`status-${testId}`}>{status}</span>
      <button data-testid={`login-${testId}`} onClick={() => void login('operator1', 'password', false)}>
        login
      </button>
      <button data-testid={`logout-${testId}`} onClick={() => void logout()}>
        logout
      </button>
    </div>
  );
}

describe('AuthContext cross-tab logout', () => {
  it('signs out every open tab when one tab logs out', async () => {
    vi.spyOn(authClient, 'refresh').mockRejectedValue(new Error('no session'));
    vi.spyOn(authClient, 'login').mockResolvedValue({ accessToken: 'token', user });
    vi.spyOn(authClient, 'logout').mockResolvedValue(undefined);

    // Two independent AuthProvider instances stand in for two browser
    // tabs of the same origin — each mounts its own BroadcastChannel, the
    // same real cross-tab wiring the app uses in a browser.
    render(
      <>
        <AuthProvider>
          <Probe testId="a" />
        </AuthProvider>
        <AuthProvider>
          <Probe testId="b" />
        </AuthProvider>
      </>,
    );

    await waitFor(() => expect(screen.getByTestId('status-a')).toHaveTextContent('signed-out'));
    await waitFor(() => expect(screen.getByTestId('status-b')).toHaveTextContent('signed-out'));

    await act(async () => {
      screen.getByTestId('login-a').click();
      screen.getByTestId('login-b').click();
    });
    await waitFor(() => expect(screen.getByTestId('status-a')).toHaveTextContent('signed-in'));
    await waitFor(() => expect(screen.getByTestId('status-b')).toHaveTextContent('signed-in'));

    // Only tab A calls logout — tab B must still transition to
    // signed-out purely from the BroadcastChannel notification.
    await act(async () => {
      screen.getByTestId('logout-a').click();
    });

    await waitFor(() => expect(screen.getByTestId('status-a')).toHaveTextContent('signed-out'));
    await waitFor(() => expect(screen.getByTestId('status-b')).toHaveTextContent('signed-out'));
    expect(authClient.logout).toHaveBeenCalledTimes(1);
  });
});
