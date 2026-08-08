use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Minimal in-memory fixed-window rate limiter, keyed by an arbitrary
/// string (a user code for per-account login throttling, or a fixed
/// constant for a single global endpoint like seed-admin). Not
/// distributed — this server runs as a single process per deployment, so
/// an in-memory map is sufficient; a multi-instance deployment would need
/// this state moved to a shared store instead.
pub struct RateLimiter {
    windows: Mutex<HashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if this attempt is allowed (and counts against the
    /// window), `false` if `key` has already used up `max_attempts` within
    /// the current `window`.
    pub fn check(&self, key: &str, max_attempts: u32, window: Duration) -> bool {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        // Opportunistic cleanup: an attacker could otherwise grow this map
        // unboundedly by trying many distinct (fake) keys purely to
        // exhaust memory.
        if windows.len() > 10_000 {
            windows.retain(|_, (_, started)| now.duration_since(*started) <= window);
        }
        let entry = windows.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) > window {
            *entry = (0, now);
        }
        if entry.0 >= max_attempts {
            return false;
        }
        entry.0 += 1;
        true
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_attempts_up_to_the_limit_then_blocks() {
        let limiter = RateLimiter::new();
        for _ in 0..5 {
            assert!(limiter.check("user-a", 5, Duration::from_secs(60)));
        }
        assert!(
            !limiter.check("user-a", 5, Duration::from_secs(60)),
            "the 6th attempt within the window should be blocked"
        );
    }

    #[test]
    fn different_keys_have_independent_windows() {
        let limiter = RateLimiter::new();
        for _ in 0..5 {
            assert!(limiter.check("user-a", 5, Duration::from_secs(60)));
        }
        assert!(
            limiter.check("user-b", 5, Duration::from_secs(60)),
            "a different key must not be blocked by user-a's exhausted window"
        );
    }

    #[test]
    fn window_resets_after_it_elapses() {
        let limiter = RateLimiter::new();
        for _ in 0..3 {
            assert!(limiter.check("user-c", 3, Duration::from_millis(20)));
        }
        assert!(!limiter.check("user-c", 3, Duration::from_millis(20)));
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            limiter.check("user-c", 3, Duration::from_millis(20)),
            "a new window should allow attempts again"
        );
    }
}
