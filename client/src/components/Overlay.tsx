import type { ReactNode } from 'react';

interface OverlayProps {
  title: string;
  onClose: () => void;
  onBack?: () => void;
  children: ReactNode;
}

export function Overlay({ title, onClose, onBack, children }: OverlayProps) {
  return (
    <div className="overlay-backdrop" onClick={onClose}>
      <div className="overlay-panel" onClick={(event) => event.stopPropagation()}>
        <div className="overlay-header">
          <span className="overlay-header__title">{title}</span>
          <button type="button" className="overlay-header__close" onClick={onBack ?? onClose} aria-label={onBack ? 'back' : 'close'}>
            {onBack ? '←' : '×'}
          </button>
        </div>
        <div className="overlay-body">{children}</div>
      </div>
    </div>
  );
}
