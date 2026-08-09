import '@testing-library/jest-dom/vitest';

// jsdom doesn't implement ResizeObserver (used by App.tsx to measure the
// fixed top bar/footer height); every real target browser does, so a
// no-op stand-in here is enough for component tests that don't assert on
// the measured size itself.
class ResizeObserverStub implements ResizeObserver {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}

globalThis.ResizeObserver ??= ResizeObserverStub;
