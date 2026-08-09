use anatolia_bis_server::{config::Config, db::AppState, middleware, routes};
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
// the env var is unset there.
fn spawn_self_ping() {
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
