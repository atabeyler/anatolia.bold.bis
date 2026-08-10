import { useEffect, useRef, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

interface OverlayProps {
  title: string;
  onClose: () => void;
  onBack?: () => void;
  children: ReactNode;
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function Overlay({ title, onClose, onBack, children }: OverlayProps) {
  const { t } = useTranslation();
  const panelRef = useRef<HTMLDivElement | null>(null);
  const closeAction = onBack ?? onClose;

  // Accessibility: move focus into the dialog on open, restore it to
  // whatever triggered the dialog on close (screen-reader and keyboard
  // users otherwise lose their place entirely once a modal opens).
  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const panel = panelRef.current;
    const firstFocusable = panel?.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
    (firstFocusable ?? panel)?.focus();
    return () => {
      previouslyFocused?.focus();
    };
  }, []);

  // Escape closes/backs out, matching standard dialog behavior; Tab is
  // trapped within the panel so keyboard focus can never silently land
  // on background content hidden behind the overlay backdrop.
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        closeAction();
        return;
      }
      if (event.key !== 'Tab') return;
      const panel = panelRef.current;
      if (!panel) return;
      const focusable = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [closeAction]);

  return (
    <div className="overlay-backdrop" onClick={onClose}>
      <div
        className="overlay-panel"
        onClick={(event) => event.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        ref={panelRef}
        tabIndex={-1}
      >
        <div className="overlay-header">
          <span className="overlay-header__title">{title}</span>
          <button
            type="button"
            className="overlay-header__close"
            onClick={closeAction}
            aria-label={onBack ? t('common.back') : t('common.close')}
          >
            {onBack ? '←' : '×'}
          </button>
        </div>
        <div className="overlay-body">{children}</div>
      </div>
    </div>
  );
}
