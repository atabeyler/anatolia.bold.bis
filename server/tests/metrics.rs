//! `GET /metrics` (madde 26 — observability): exercises the endpoint
//! end to end, including the optional `METRICS_TOKEN` gate.

use anatolia_bis_server::{db::AppState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tokio::sync::Mutex;
use tower::ServiceExt;

static ENV_GUARD: Mutex<()> = Mutex::const_new(());

#[tokio::test]
async fn metrics_endpoint_is_open_by_default_and_reports_prometheus_text() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("METRICS_TOKEN");
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    // Generate at least one HTTP request the metrics middleware can
    // record before checking the snapshot.
    app.clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(body.contains("http_requests_total"));
}

#[tokio::test]
async fn metrics_endpoint_requires_the_configured_token_when_set() {
    let _guard = ENV_GUARD.lock().await;
    std::env::set_var("METRICS_TOKEN", "metrics-test-secret");
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .header("authorization", "Bearer metrics-test-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    std::env::remove_var("METRICS_TOKEN");
}
