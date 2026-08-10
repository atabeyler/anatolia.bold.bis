use anatolia_bis_server::{config::Config, db, db::AppState, middleware, routes};
use axum::http::{HeaderName, Method};
use axum::middleware::from_fn;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

const REQUEST_ID_HEADER: &str = "x-request-id";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env();
    let request_id_header = HeaderName::from_static(REQUEST_ID_HEADER);

    // Credentialed (cookie-carrying) requests, per the CORS spec, cannot be
    // paired with a wildcard origin or header list — both must be
    // explicit, or browsers refuse to send the refresh-token cookie.
    let cors = if config.allowed_origins.is_empty() {
        tracing::warn!("ALLOWED_ORIGINS is unset; CORS will reject all cross-origin requests");
        CorsLayer::new()
    } else {
        let origins: Vec<_> = config
            .allowed_origins
            .iter()
            .filter_map(|origin| origin.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ])
            .allow_headers([
                HeaderName::from_static("content-type"),
                HeaderName::from_static("authorization"),
                HeaderName::from_static("x-seed-token"),
            ])
            .allow_credentials(true)
    };

    let state = AppState::new(&config)
        .await
        .expect("failed to initialize application state");

    // Serves the built frontend from the same process/origin as the API —
    // one deployed service, one URL, no separate static-site resource.
    // Defaults to the path a local `cd server && cargo run` finds the
    // sibling client/dist build at; Render's single-service deploy (see
    // render.yaml) runs from the repository root instead and overrides
    // this to "client/dist". Any request that isn't a static asset falls
    // through to index.html so client-side routing resolves on a hard
    // refresh/deep link, exactly like the SPA fallback already used for
    // the local Docker Compose nginx config.
    let static_dir = std::env::var("STATIC_DIR").unwrap_or_else(|_| "../client/dist".to_string());
    let index_file = format!("{static_dir}/index.html");
    let serve_frontend = ServeDir::new(&static_dir).not_found_service(ServeFile::new(index_file));

    spawn_retention_job(state.clone());

    let app = routes::router(state)
        .fallback_service(serve_frontend)
        .layer(from_fn(middleware::security_headers))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(cors)
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid));

    let listener = TcpListener::bind(("0.0.0.0", config.port))
        .await
        .expect("failed to bind TCP listener");

    tracing::info!(port = config.port, "anatolia-bis-server listening");

    spawn_self_ping();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("shutdown signal received");
}

// Render's free plan spins the whole web service down after ~15 minutes
// without external traffic; the next request then pays a cold-start (new
// container, fresh DB connection) that can take 20-60s and surfaces to
// users as a page that looks entirely unresponsive. Self-pinging the
// public URL (which Render always injects as RENDER_EXTERNAL_URL) counts
// as traffic and keeps the instance warm. This cannot eliminate the very
// first cold start after a genuinely idle period — only prevent repeated
// ones — and is a no-op outside Render (e.g. desktop/local dev), since
// the env var is unset there. Opt-in via `ENABLE_SELF_PING=true` — a
// background process that periodically calls back out to its own public
// URL is surprising, free-plan-specific behavior that a deployment
// shouldn't get by default just because `RENDER_EXTERNAL_URL` happens to
// be set (e.g. a paid Render plan, or any other host that also injects a
// same-shaped external-URL variable). This project's own `render.yaml`
// sets `ENABLE_SELF_PING=true` explicitly for the free-plan service it
// deploys, so the live deployment's behavior is unchanged by this
// default.
// Deletes expired `sessions`/`approval_tokens` rows on a fixed interval so
// they don't accumulate forever — neither table is ever read for anything
// once its `expires_at` has passed (see `db::purge_expired_auth_records`).
// Runs an initial pass shortly after startup rather than only after the
// first full interval, so a long-running deployment doesn't carry a large
// startup backlog for an hour before it's first cleaned up. Configurable
// via `RETENTION_JOB_INTERVAL_SECS` (default 3600); `RETENTION_JOB_ENABLED
// =false` disables it entirely, e.g. for a read-only replica or a test
// environment that doesn't want a background writer.
fn spawn_retention_job(state: AppState) {
    if std::env::var("RETENTION_JOB_ENABLED").as_deref() == Ok("false") {
        tracing::info!("retention job disabled via RETENTION_JOB_ENABLED=false");
        return;
    }
    let interval_secs: u64 = std::env::var("RETENTION_JOB_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);
    tokio::spawn(async move {
        let mut first_run = true;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(if first_run {
                30
            } else {
                interval_secs
            }))
            .await;
            first_run = false;
            match db::purge_expired_auth_records(&state.backend).await {
                Ok((sessions, approval_tokens)) if sessions > 0 || approval_tokens > 0 => {
                    tracing::info!(
                        sessions,
                        approval_tokens,
                        "retention job purged expired rows"
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(error = %err, "retention job failed");
                }
            }
        }
    });
}

fn spawn_self_ping() {
    if std::env::var("ENABLE_SELF_PING").as_deref() != Ok("true") {
        tracing::info!("self-ping disabled by default; set ENABLE_SELF_PING=true to enable");
        return;
    }
    let Ok(external_url) = std::env::var("RENDER_EXTERNAL_URL") else {
        return;
    };
    let health_url = format!("{}/api/health", external_url.trim_end_matches('/'));
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(150)).await;
            if let Err(err) = client.get(&health_url).send().await {
                tracing::warn!(error = %err, "self-ping failed");
            }
        }
    });
}
