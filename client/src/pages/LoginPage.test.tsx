import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { AuthProvider } from '../features/auth/AuthContext';
import i18n from '../i18n/config';
import * as authClient from '../services/authClient';
import { LoginPage } from './LoginPage';

function renderLoginPage() {
  return render(
    <AuthProvider>
      <LoginPage />
    </AuthProvider>,
  );
}

describe('LoginPage', () => {
  it('shows the sign-in fields by default and switches to sign-up fields', async () => {
    vi.spyOn(authClient, 'refresh').mockRejectedValue(new Error('no session'));
    await i18n.changeLanguage('en');
    const { container } = renderLoginPage();

    expect(screen.getByText('User code')).toBeInTheDocument();
    expect(screen.queryByText('National ID No')).not.toBeInTheDocument();

    const toggleButtons = container.querySelectorAll('.auth-mode-toggle button');
    fireEvent.click(toggleButtons[1]);

    expect(screen.getByText('National ID No')).toBeInTheDocument();
  });

  it('shows a translated error message when login fails', async () => {
    vi.spyOn(authClient, 'refresh').mockRejectedValue(new Error('no session'));
    vi.spyOn(authClient, 'login').mockRejectedValue({
      isAxiosError: true,
      response: { data: { code: 'UNAUTHORIZED', messageKey: 'errors.invalidCredentials', requestId: 'r1' } },
    });
    await i18n.changeLanguage('en');
    const { container } = renderLoginPage();

    const userCodeInput = container.querySelector('input[maxlength="20"]') as HTMLInputElement;
    const passwordInput = container.querySelector('input[type="password"]') as HTMLInputElement;
    fireEvent.change(userCodeInput, { target: { value: 'OPERATOR1' } });
    fireEvent.change(passwordInput, { target: { value: 'WrongPassword1!' } });

    const form = container.querySelector('form.auth-panel') as HTMLFormElement;
    await act(async () => {
      fireEvent.submit(form);
    });

    await waitFor(() => expect(screen.getByText('Invalid user code or password.')).toBeInTheDocument());
  });

  it('shows the MFA challenge step when login requires a TOTP code, and verifies it', async () => {
    vi.spyOn(authClient, 'refresh').mockRejectedValue(new Error('no session'));
    vi.spyOn(authClient, 'login').mockResolvedValue({
      mfaRequired: true,
      mfaToken: 'challenge-token',
      userCode: 'ADMIN1',
    });
    const verifySpy = vi.spyOn(authClient, 'mfaChallengeVerify').mockResolvedValue({
      accessToken: 'access-token',
      user: {
        id: 'u1',
        userCode: 'ADMIN1',
        email: 'admin@example.test',
        role: 'SYSTEM_ADMIN',
        firstName: 'Ada',
        lastName: 'Admin',
      },
    });
    await i18n.changeLanguage('en');
    const { container } = renderLoginPage();

    const userCodeInput = container.querySelector('input[maxlength="20"]') as HTMLInputElement;
    const passwordInput = container.querySelector('input[type="password"]') as HTMLInputElement;
    fireEvent.change(userCodeInput, { target: { value: 'ADMIN1' } });
    fireEvent.change(passwordInput, { target: { value: 'AdminPass1!' } });
    const form = container.querySelector('form.auth-panel') as HTMLFormElement;
    await act(async () => {
      fireEvent.submit(form);
    });

    await waitFor(() => expect(screen.getByText('Verification code')).toBeInTheDocument());

    const codeInput = container.querySelector('form.auth-panel input') as HTMLInputElement;
    fireEvent.change(codeInput, { target: { value: '123456' } });
    const mfaForm = container.querySelector('form.auth-panel') as HTMLFormElement;
    await act(async () => {
      fireEvent.submit(mfaForm);
    });

    await waitFor(() => expect(verifySpy).toHaveBeenCalledWith('challenge-token', '123456'));
  });
});
