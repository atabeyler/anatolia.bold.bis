use anatolia_bis_server::{config::Config, db::AppState, middleware, routes};
use axum::http::{HeaderName, Method};
use axum::middleware::from_fn;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
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
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([
                HeaderName::from_static("content-type"),
                HeaderName::from_static("authorization"),
                HeaderName::from_static("x-seed-token"),
            ])
            .allow_credentials(true)
    };

    let state = AppState::new().await.expect("failed to initialize application state");

    let app = routes::router(state)
        .layer(from_fn(middleware::security_headers))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(cors)
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid));

    let listener = TcpListener::bind(("0.0.0.0", config.port))
        .await
        .expect("failed to bind TCP listener");

    tracing::info!(port = config.port, "anatolia-bis-server listening");

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
