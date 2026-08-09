import { describe, expect, it } from 'vitest';

import { createAuthBroadcastChannel, isSignedOutMessage, postSignedOut } from './authBroadcast';

describe('authBroadcast', () => {
  it('delivers a signed-out message to every other channel of the same name', async () => {
    const sender = createAuthBroadcastChannel();
    const receiver = createAuthBroadcastChannel();
    expect(sender).not.toBeNull();
    expect(receiver).not.toBeNull();

    const received = new Promise<MessageEvent>((resolve) => {
      receiver!.addEventListener('message', resolve, { once: true });
    });

    postSignedOut(sender);
    const event = await received;
    expect(isSignedOutMessage(event.data)).toBe(true);

    sender!.close();
    receiver!.close();
  });

  it('is a no-op when passed a null channel', () => {
    expect(() => postSignedOut(null)).not.toThrow();
  });

  it('rejects messages that are not the signed-out shape', () => {
    expect(isSignedOutMessage(null)).toBe(false);
    expect(isSignedOutMessage(undefined)).toBe(false);
    expect(isSignedOutMessage({ type: 'something-else' })).toBe(false);
    expect(isSignedOutMessage('signed-out')).toBe(false);
  });
});
