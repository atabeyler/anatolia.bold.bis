use axum::Json;
use chrono::{SecondsFormat, Utc};
use serde::Serialize;

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
