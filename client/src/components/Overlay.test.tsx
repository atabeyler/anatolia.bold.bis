import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { Overlay } from './Overlay';
import i18n from '../i18n/config';

describe('Overlay', () => {
  it('exposes itself as an accessible modal dialog', async () => {
    await i18n.changeLanguage('en');
    render(
      <Overlay title="Settings" onClose={vi.fn()}>
        <p>Body content</p>
      </Overlay>,
    );
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAttribute('aria-label', 'Settings');
  });

  it('closes on Escape', async () => {
    await i18n.changeLanguage('en');
    const onClose = vi.fn();
    render(
      <Overlay title="Settings" onClose={onClose}>
        <p>Body content</p>
      </Overlay>,
    );
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('calls onBack instead of onClose on Escape when onBack is provided', async () => {
    await i18n.changeLanguage('en');
    const onClose = vi.fn();
    const onBack = vi.fn();
    render(
      <Overlay title="Language" onClose={onClose} onBack={onBack}>
        <p>Body content</p>
      </Overlay>,
    );
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onBack).toHaveBeenCalledTimes(1);
    expect(onClose).not.toHaveBeenCalled();
  });

  it('moves focus into the dialog panel on open (the first focusable element, its own close button)', async () => {
    await i18n.changeLanguage('en');
    render(
      <Overlay title="Settings" onClose={vi.fn()}>
        <button type="button">First action</button>
      </Overlay>,
    );
    // The close button is the first focusable element in DOM order (it's
    // in the header, before the body content) — confirms focus moved
    // somewhere inside the dialog, not left on the page behind it.
    expect(document.activeElement).toHaveAccessibleName('Close');
    expect(screen.getByRole('dialog')).toContainElement(document.activeElement as HTMLElement);
  });

  it('gives the close button a translated, non-empty accessible name', async () => {
    await i18n.changeLanguage('en');
    render(
      <Overlay title="Settings" onClose={vi.fn()}>
        <p>Body content</p>
      </Overlay>,
    );
    expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument();
  });
});
