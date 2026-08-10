use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{SecondsFormat, Utc};
use serde::Serialize;

use crate::db::{AppState, DbBackend};

/// Commit SHA embedded at compile time by build.rs. This is how a
/// deployment (e.g. on Render) is verified to have actually picked up a
/// given push, rather than assuming from push time alone.
const GIT_COMMIT_SHA: &str = env!("GIT_COMMIT_SHA");

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
    timestamp: String,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: GIT_COMMIT_SHA,
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadyResponse {
    status: &'static str,
    version: &'static str,
    timestamp: String,
    /// Which `BiometricProvider` is active — `"mock"` (no real face
    /// comparison; see `docs/SECURITY_ARCHITECTURE.md`) or `"onnx"` (real,
    /// server-side YuNet/SFace inference — see item 1 in
    /// `docs/HARDENING_CHECKLIST.md`). Reported so a deployment's actual
    /// biometric capability is visible from the outside rather than only
    /// inferred from `BIOMETRIC_PROVIDER`, which this endpoint never
    /// echoes directly to avoid implying it as a trusted client input.
    biometric_provider: &'static str,
    /// `"pgvector-hnsw"` when biometric search uses the indexed
    /// PostgreSQL path, `"brute-force"` when it falls back to the
    /// in-memory linear scan (always true on SQLite; on Postgres, only if
    /// the `vector` extension could not be enabled) — see item 2 in
    /// `docs/HARDENING_CHECKLIST.md`.
    biometric_search: &'static str,
}

/// Liveness (`/api/health`) only says the process is running; it never
/// touches the database, so it stays `200` even while the database is
/// unreachable. Readiness is the stricter check a load balancer or
/// orchestrator should gate traffic on: it runs a trivial query against
/// the real backend and reports `503` if that fails, instead of routing
/// requests to an instance that can't actually serve them. It never
/// returns `503` over the biometric provider or search mode, though —
/// both are read-only facts about how this instance is configured, not
/// signals of a degraded, unready instance.
pub async fn ready(State(state): State<AppState>) -> Response {
    let db_ok = match &state.backend {
        DbBackend::Postgres(pool) => sqlx::query("SELECT 1").execute(pool).await.is_ok(),
        DbBackend::Sqlite(pool) => sqlx::query("SELECT 1").execute(pool).await.is_ok(),
    };
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let biometric_provider = state.biometric_provider_name;
    let biometric_search = if state.pgvector_search_ready {
        "pgvector-hnsw"
    } else {
        "brute-force"
    };
    if db_ok {
        Json(ReadyResponse {
            status: "ready",
            version: GIT_COMMIT_SHA,
            timestamp,
            biometric_provider,
            biometric_search,
        })
        .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "not_ready",
                version: GIT_COMMIT_SHA,
                timestamp,
                biometric_provider,
                biometric_search,
            }),
        )
            .into_response()
    }
}
