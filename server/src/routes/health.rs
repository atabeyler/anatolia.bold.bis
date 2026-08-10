use std::sync::LazyLock;
use std::time::Instant;

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

/// Set the first time anything touches it, which in practice is this
/// process's first `/api/health/ready` call — close enough to true
/// process start (within the first request's latency) without needing to
/// thread a start time through `AppState` from `main.rs`.
static PROCESS_START: LazyLock<Instant> = LazyLock::new(Instant::now);

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DbPoolStatus {
    /// Total connections currently open in the pool (in use + idle).
    size: u32,
    /// Connections open but not currently checked out by a query.
    idle: u32,
}

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
    /// Seconds since this process's first readiness check — an
    /// approximation of process uptime (see `PROCESS_START`), useful for
    /// spotting an unexpected restart without needing external
    /// orchestrator-level tracking.
    uptime_seconds: u64,
    db_pool: DbPoolStatus,
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
    let db_pool = match &state.backend {
        DbBackend::Postgres(pool) => DbPoolStatus {
            size: pool.size(),
            idle: pool.num_idle() as u32,
        },
        DbBackend::Sqlite(pool) => DbPoolStatus {
            size: pool.size(),
            idle: pool.num_idle() as u32,
        },
    };
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let biometric_provider = state.biometric_provider_name;
    let biometric_search = if state.pgvector_search_ready {
        "pgvector-hnsw"
    } else {
        "brute-force"
    };
    let uptime_seconds = PROCESS_START.elapsed().as_secs();
    if db_ok {
        Json(ReadyResponse {
            status: "ready",
            version: GIT_COMMIT_SHA,
            timestamp,
            biometric_provider,
            biometric_search,
            uptime_seconds,
            db_pool,
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
                uptime_seconds,
                db_pool,
            }),
        )
            .into_response()
    }
}
