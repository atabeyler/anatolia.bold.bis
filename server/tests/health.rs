use anatolia_bis_server::{db::AppState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_ok_status_and_version() {
    let app = routes::router(AppState::for_tests().await);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "ok");
    assert!(json["version"].is_string());
    assert!(json["timestamp"].is_string());
}

#[tokio::test]
async fn ready_reports_the_active_biometric_provider_and_search_mode() {
    let app = routes::router(AppState::for_tests().await);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["status"], "ready");
    // `for_tests()` always runs the mock provider against SQLite — no
    // pgvector index is possible there, so both fields must reflect that.
    assert_eq!(json["biometricProvider"], "mock");
    assert_eq!(json["biometricSearch"], "brute-force");
    assert!(json["uptimeSeconds"].is_number());
    assert!(json["dbPool"]["size"].as_u64().unwrap() >= 1);
    assert!(json["dbPool"]["idle"].is_number());
}
