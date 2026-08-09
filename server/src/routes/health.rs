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
}

/// Liveness (`/api/health`) only says the process is running; it never
/// touches the database, so it stays `200` even while the database is
/// unreachable. Readiness is the stricter check a load balancer or
/// orchestrator should gate traffic on: it runs a trivial query against
/// the real backend and reports `503` if that fails, instead of routing
/// requests to an instance that can't actually serve them.
pub async fn ready(State(state): State<AppState>) -> Response {
    let db_ok = match &state.backend {
        DbBackend::Postgres(pool) => sqlx::query("SELECT 1").execute(pool).await.is_ok(),
        DbBackend::Sqlite(pool) => sqlx::query("SELECT 1").execute(pool).await.is_ok(),
    };
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    if db_ok {
        Json(ReadyResponse {
            status: "ready",
            version: GIT_COMMIT_SHA,
            timestamp,
        })
        .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "not_ready",
                version: GIT_COMMIT_SHA,
                timestamp,
            }),
        )
            .into_response()
    }
}
