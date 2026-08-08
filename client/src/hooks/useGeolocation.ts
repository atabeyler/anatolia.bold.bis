import { useEffect, useState } from 'react';

export type GeolocationStatus = 'idle' | 'requesting' | 'granted' | 'denied' | 'unsupported';

export interface GeolocationCoords {
  latitude: number;
  longitude: number;
}

let lastKnownCoords: GeolocationCoords | null = null;

/** Exposed so a future case/candidate-report feature can attach the
 * operator's last captured location without re-requesting permission. */
export function getLastKnownLocation(): GeolocationCoords | null {
  return lastKnownCoords;
}

/** Requests the browser's real geolocation once, on mount. There is no
 * synthetic fallback coordinate on denial/error — callers must handle
 * `status` and show nothing (or an explicit "unavailable" message)
 * rather than a fabricated location. */
export function useGeolocation() {
  const [status, setStatus] = useState<GeolocationStatus>('idle');
  const [coords, setCoords] = useState<GeolocationCoords | null>(lastKnownCoords);

  useEffect(() => {
    if (!navigator.geolocation) {
      setStatus('unsupported');
      return;
    }
    setStatus('requesting');
    navigator.geolocation.getCurrentPosition(
      (position) => {
        const next = { latitude: position.coords.latitude, longitude: position.coords.longitude };
        lastKnownCoords = next;
        setCoords(next);
        setStatus('granted');
      },
      () => {
        setStatus('denied');
      },
      { enableHighAccuracy: false, timeout: 15_000, maximumAge: 300_000 },
    );
  }, []);

  return { status, coords };
}

export function formatLatitude(value: number): string {
  return `${Math.abs(value).toFixed(4)}°${value >= 0 ? 'N' : 'S'}`;
}

export function formatLongitude(value: number): string {
  return `${Math.abs(value).toFixed(4)}°${value >= 0 ? 'E' : 'W'}`;
}
