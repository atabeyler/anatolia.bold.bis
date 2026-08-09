interface LogoProps {
  /** Smaller footprint for the fixed top bar, where the full hero-sized
   * mark would be too tall for a persistent, always-visible row. */
  compact?: boolean;
}

export function Logo({ compact = false }: LogoProps) {
  return (
    <div className={compact ? 'brand-logo brand-logo--compact' : 'brand-logo'}>
      <div className="brand-logo__ping" />
      <div className="brand-logo__ping brand-logo__ping--delay1" />
      <div className="brand-logo__ping brand-logo__ping--delay2" />
      <div className="brand-logo__ring" />
      <div className="brand-logo__sweep" />
      <div className="brand-logo__badge">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#ffffff" strokeWidth="1.6" strokeLinecap="round">
          <circle cx="12" cy="12" r="10" />
          <ellipse cx="12" cy="12" rx="6" ry="14.29" />
          <path d="M2 12h20" />
          <circle cx="12" cy="12" r="1.8" fill="var(--color-success)" stroke="none" />
        </svg>
      </div>
    </div>
  );
}
