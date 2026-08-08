export function Logo() {
  return (
    <div className="brand-logo">
      <div className="brand-logo__ring" />
      <div className="brand-logo__badge">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#ffffff" strokeWidth="1.6" strokeLinecap="round">
          <circle cx="12" cy="12" r="10" />
          <ellipse cx="12" cy="12" rx="6" ry="14.29" />
          <path d="M2 12h20" />
          <circle cx="12" cy="12" r="1.8" fill="var(--color-accent)" stroke="none" />
        </svg>
      </div>
    </div>
  );
}
