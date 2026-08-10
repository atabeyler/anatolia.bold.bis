//! Prometheus-compatible metrics (madde 26 — observability). A single
//! process-wide `PrometheusHandle` (installed once at startup by
//! `init()`) backs both the metric-recording call sites scattered across
//! the codebase (via the `metrics` crate's global recorder — `counter!`/
//! `histogram!` work anywhere without threading a handle through) and the
//! `GET /metrics` endpoint, which renders the current snapshot.
//!
//! Every label used here is a fixed, small-cardinality value (HTTP
//! method, a route *template* like `/api/v1/candidates/:id`, a status
//! code, a provider name) — never a raw path, user id, IP address, or any
//! other unbounded or personally-identifying value. This matches the
//! existing structured-logging rule in `docs/SECURITY_ARCHITECTURE.md`:
//! no PII in anything that isn't access-controlled the way `/api/v1/audit`
//! is. `/metrics` itself is intentionally unauthenticated by default
//! (the conventional Prometheus scrape posture — the exported values
//! contain no PII to protect), but an optional bearer token
//! (`METRICS_TOKEN`) can restrict it, since some deployments still prefer
//! not to expose operational counts on a public path — see
//! `docs/ENVIRONMENT.md`.

use std::sync::OnceLock;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

use crate::db::AppState;

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Applied via `route_layer` (after route matching, so `MatchedPath` is
/// available — see `routes::router`). Labels are the HTTP method, the
/// matched route *template* (e.g. `/api/v1/candidates/:candidate_id`, not
/// the concrete path with a real id in it — bounded cardinality, no PII),
/// and the response status code.
pub async fn http_metrics_middleware(request: Request, next: Next) -> Response {
    let method = request.method().to_string();
    let path = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "unmatched".to_string());

    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let elapsed = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    metrics::counter!(
        "http_requests_total",
        "method" => method.clone(),
        "path" => path.clone(),
        "status" => status,
    )
    .increment(1);
    metrics::histogram!(
        "http_request_duration_seconds",
        "method" => method,
        "path" => path,
    )
    .record(elapsed);

    response
}

/// Installs the global Prometheus recorder on first call and returns its
/// handle; every later call (including once per `AppState::for_tests()`
/// within the same test binary, since each test builds its own state)
/// just returns a clone of the already-installed handle rather than
/// re-installing — `metrics::set_global_recorder` can only ever succeed
/// once per process.
pub fn init() -> PrometheusHandle {
    HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install the Prometheus metrics recorder")
        })
        .clone()
}

/// `GET /metrics` — the current snapshot in Prometheus text exposition
/// format. If `METRICS_TOKEN` is set, requires `Authorization: Bearer
/// <token>` (constant-time compared, same helper `auth`/`admin` seed-token
/// checks use); if unset, the endpoint is open, matching conventional
/// Prometheus scrape deployment (no PII is ever exported here to
/// protect — see the module doc comment).
pub async fn metrics_route(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Ok(expected) = std::env::var("METRICS_TOKEN") {
        if !expected.trim().is_empty() {
            let provided = headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("");
            if !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
    }
    state.metrics_handle.render().into_response()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_identical_bytes() {
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
    }

    #[test]
    fn constant_time_eq_rejects_different_bytes() {
        assert!(!constant_time_eq(b"secret-token", b"wrong-token!"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq(b"short", b"a-much-longer-value"));
    }
}
