//! Generic timeout/retry/circuit-breaker behavior for real OSINT
//! providers. Deliberately not
//! provider-specific: `RealWebSearchProvider`/`RealNewsProvider` both
//! wrap their HTTP call through `CircuitBreaker::call`, so a struggling
//! upstream (timeouts, 5xx errors) degrades the same way regardless of
//! which provider it is — a few retried failures, then the breaker opens
//! and every further call fails fast (no network attempt at all) until
//! the cooldown elapses, protecting both the OSINT collection request's
//! own latency and the upstream service from being hammered while it is
//! unhealthy.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::OsintError;

struct BreakerState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

/// Opens after `failure_threshold` consecutive failures, stays open
/// (failing fast, no network attempt) for `cooldown`, then allows a
/// single trial call — success closes it, failure reopens it for another
/// `cooldown`. One instance is meant to be shared (via the owning
/// provider struct) across every call a given provider makes, not
/// recreated per-request.
pub struct CircuitBreaker {
    failure_threshold: u32,
    cooldown: Duration,
    state: Mutex<BreakerState>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            failure_threshold,
            cooldown,
            state: Mutex::new(BreakerState {
                consecutive_failures: 0,
                open_until: None,
            }),
        }
    }

    fn is_open(&self) -> bool {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        matches!(state.open_until, Some(until) if Instant::now() < until)
    }

    fn record_success(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.consecutive_failures = 0;
        state.open_until = None;
    }

    fn record_failure(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.consecutive_failures += 1;
        if state.consecutive_failures >= self.failure_threshold {
            state.open_until = Some(Instant::now() + self.cooldown);
        }
    }

    /// Runs `attempt` (one HTTP call) up to `max_attempts` times with a
    /// short delay between retries, through the breaker. Fails fast with
    /// `ProviderUnavailable` — no call to `attempt` at all — while the
    /// breaker is open.
    pub async fn call<F, Fut>(
        &self,
        provider_name: &str,
        max_attempts: u32,
        retry_delay: Duration,
        mut attempt: F,
    ) -> Result<super::EvidenceItems, OsintError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<super::EvidenceItems, OsintError>>,
    {
        if self.is_open() {
            return Err(OsintError::ProviderUnavailable(format!(
                "{provider_name}: circuit breaker open (too many recent failures); \
                 not attempting a request"
            )));
        }
        let mut last_err = None;
        for attempt_number in 1..=max_attempts.max(1) {
            match attempt().await {
                Ok(items) => {
                    self.record_success();
                    return Ok(items);
                }
                Err(err) => {
                    tracing::warn!(
                        provider = provider_name,
                        attempt = attempt_number,
                        error = %err,
                        "OSINT provider request failed"
                    );
                    last_err = Some(err);
                    if attempt_number < max_attempts {
                        tokio::time::sleep(retry_delay).await;
                    }
                }
            }
        }
        self.record_failure();
        Err(last_err.unwrap_or_else(|| {
            OsintError::Internal("provider call failed with no recorded error".to_string())
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn a_successful_call_resets_the_failure_count() {
        let breaker = CircuitBreaker::new(3, Duration::from_millis(50));
        let result = breaker
            .call("test", 1, Duration::from_millis(1), || async {
                Ok(Vec::new())
            })
            .await;
        assert!(result.is_ok());
        assert!(!breaker.is_open());
    }

    #[tokio::test]
    async fn opens_after_the_failure_threshold_and_fails_fast() {
        let breaker = CircuitBreaker::new(2, Duration::from_secs(60));
        let calls = AtomicU32::new(0);
        for _ in 0..2 {
            let _ = breaker
                .call("test", 1, Duration::from_millis(1), || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Err(OsintError::Internal("simulated".to_string())) }
                })
                .await;
        }
        assert!(breaker.is_open());
        // A further call must fail immediately, without invoking `attempt`.
        let calls_before = calls.load(Ordering::SeqCst);
        let result = breaker
            .call("test", 1, Duration::from_millis(1), || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Ok(Vec::new()) }
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), calls_before);
    }

    #[tokio::test]
    async fn retries_up_to_max_attempts_before_failing() {
        let breaker = CircuitBreaker::new(10, Duration::from_secs(60));
        let calls = AtomicU32::new(0);
        let result = breaker
            .call("test", 3, Duration::from_millis(1), || {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(OsintError::Internal("simulated".to_string())) }
            })
            .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_retry_that_eventually_succeeds_returns_ok() {
        let breaker = CircuitBreaker::new(10, Duration::from_secs(60));
        let calls = AtomicU32::new(0);
        let result = breaker
            .call("test", 3, Duration::from_millis(1), || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 1 {
                        Err(OsintError::Internal("simulated".to_string()))
                    } else {
                        Ok(Vec::new())
                    }
                }
            })
            .await;
        assert!(result.is_ok());
    }
}
