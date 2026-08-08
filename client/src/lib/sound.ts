const STORAGE_KEY = 'anatolia_sound_enabled';

export function isSoundEnabled(): boolean {
  return localStorage.getItem(STORAGE_KEY) === '1';
}

export function setSoundEnabled(enabled: boolean): void {
  localStorage.setItem(STORAGE_KEY, enabled ? '1' : '0');
}

/** Short synthesized chime — no audio asset needed. Used for notification
 * feedback (e.g. a successful sign-in) when the user has sound enabled. */
export function playChime(): void {
  const AudioContextClass = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!AudioContextClass) {
    return;
  }
  const ctx = new AudioContextClass();
  const oscillator = ctx.createOscillator();
  const gain = ctx.createGain();
  oscillator.type = 'sine';
  oscillator.frequency.value = 660;
  gain.gain.setValueAtTime(0.0001, ctx.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.15, ctx.currentTime + 0.01);
  gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.3);
  oscillator.connect(gain).connect(ctx.destination);
  oscillator.start();
  oscillator.stop(ctx.currentTime + 0.32);
  oscillator.onended = () => void ctx.close();
}

export function playChimeIfEnabled(): void {
  if (isSoundEnabled()) {
    playChime();
  }
}
