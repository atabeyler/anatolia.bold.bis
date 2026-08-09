// Cross-tab sign-out sync. Without this, logging out (or being logged out
// by an admin ban) in one tab leaves every other open tab of the same
// browser holding a stale access token in memory until its next failed
// request. `BroadcastChannel` is same-origin, same-browser only — it never
// crosses devices or users, so it adds no new exposure beyond what a single
// tab already had.

const CHANNEL_NAME = 'anatolia-bis-auth';

interface AuthBroadcastMessage {
  type: 'signed-out';
}

// `null` on a runtime without `BroadcastChannel` (older Safari, some
// embedded webviews) — callers must treat that as "no cross-tab sync
// available" rather than throwing, since this is a hardening addition,
// not a requirement for auth to function within a single tab.
export function createAuthBroadcastChannel(): BroadcastChannel | null {
  if (typeof BroadcastChannel === 'undefined') {
    return null;
  }
  return new BroadcastChannel(CHANNEL_NAME);
}

export function postSignedOut(channel: BroadcastChannel | null): void {
  const message: AuthBroadcastMessage = { type: 'signed-out' };
  channel?.postMessage(message);
}

export function isSignedOutMessage(data: unknown): data is AuthBroadcastMessage {
  return (
    typeof data === 'object' &&
    data !== null &&
    (data as Partial<AuthBroadcastMessage>).type === 'signed-out'
  );
}
