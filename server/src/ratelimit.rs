use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Rate-limiter backend abstraction (see CLAUDE.md's provider-abstraction
/// pattern, already used for `BiometricProvider`/vector search). Only
/// `InMemoryRateLimiter` exists today — this server runs as a single
/// process per deployment, so an in-memory map is sufficient — but a
/// multi-instance deployment needs this state moved to a shared store
/// (Redis, or a database table), which this trait boundary makes a
/// drop-in change rather than a rewrite of every call site.
pub trait RateLimiterBackend: Send + Sync {
    /// Returns `true` if this attempt is allowed (and counts against the
    /// window), `false` if `key` has already used up `max_attempts` within
    /// the current `window`.
    fn check(&self, key: &str, max_attempts: u32, window: Duration) -> bool;
}

/// Minimal in-memory fixed-window rate limiter, keyed by an arbitrary
/// string (a user code for per-account login throttling, or a fixed
/// constant for a single global endpoint like seed-admin).
pub struct InMemoryRateLimiter {
    windows: Mutex<HashMap<String, (u32, Instant)>>,
}

impl InMemoryRateLimiter {
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }
}

impl RateLimiterBackend for InMemoryRateLimiter {
    fn check(&self, key: &str, max_attempts: u32, window: Duration) -> bool {
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

impl Default for InMemoryRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Backwards-compatible alias — most of the codebase (and `AppState`)
/// only ever needs "the configured rate limiter", not this specific
/// backend, and goes through `RateLimiterBackend` for that.
pub type RateLimiter = InMemoryRateLimiter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_attempts_up_to_the_limit_then_blocks() {
        let limiter = InMemoryRateLimiter::new();
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
        let limiter = InMemoryRateLimiter::new();
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
        let limiter = InMemoryRateLimiter::new();
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

    /// A second, trivial backend — proves `RateLimiterBackend` is a real
    /// swappable interface, not just a trait wrapping one struct.
    struct AlwaysAllow;
    impl RateLimiterBackend for AlwaysAllow {
        fn check(&self, _key: &str, _max_attempts: u32, _window: Duration) -> bool {
            true
        }
    }

    #[test]
    fn a_different_backend_implementation_can_be_used_interchangeably() {
        let limiter: Box<dyn RateLimiterBackend> = Box::new(AlwaysAllow);
        for _ in 0..100 {
            assert!(limiter.check("anyone", 1, Duration::from_secs(60)));
        }
    }
}
