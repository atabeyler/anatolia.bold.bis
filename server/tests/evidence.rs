//! Evidence collection endpoints (P2 OSINT appendix): run under the mock
//! provider set by default, so these tests exercise the wiring —
//! permission gates, candidate lookup, storage, and listing — without
//! any real external request. Provider failure isolation itself is
//! covered by unit tests in `src/osint/mod.rs`.

use anatolia_bis_server::{db::AppState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tower::ServiceExt;

static ENV_GUARD: Mutex<()> = Mutex::const_new(());

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn json_request(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn seed_admin_and_login(app: &axum::Router, user_code: &str) -> String {
    std::env::set_var("ADMIN_SEED_TOKEN", "evidence-test-seed-token");
    std::env::set_var("ADMIN_USER_CODE", user_code);
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "evidence-admin@example.test");

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "evidence-test-seed-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "userCode": user_code, "password": "AdminPass1!" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(response).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn create_candidate(app: &axum::Router, token: &str, reference_code: &str) -> String {
    let created = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/candidates",
            token,
            json!({ "referenceCode": reference_code, "fullName": "Evidence Test" }),
        ))
        .await
        .unwrap();
    body_json(created).await["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn collecting_evidence_stores_items_from_every_mock_provider() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "EVIDADM1").await;
    let candidate_id = create_candidate(&app, &token, "RC-EVIDENCE-001").await;

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/candidates/{candidate_id}/evidence/collect"),
            &token,
            json!({ "query": "Jane Doe" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    let items = payload["items"].as_array().unwrap();
    // MockWebSearchProvider, MockNewsProvider, MockSocialProvider each
    // return exactly one item.
    assert_eq!(items.len(), 3);
    assert!(payload["providerErrors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn listing_evidence_returns_previously_collected_items() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "EVIDADM2").await;
    let candidate_id = create_candidate(&app, &token, "RC-EVIDENCE-002").await;

    app.clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/candidates/{candidate_id}/evidence/collect"),
            &token,
            json!({ "query": "John Smith" }),
        ))
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/candidates/{candidate_id}/evidence"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    assert_eq!(payload["items"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn collecting_evidence_for_an_unknown_candidate_is_not_found() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "EVIDADM3").await;

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/candidates/does-not-exist/evidence/collect",
            &token,
            json!({ "query": "Anyone" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn collecting_evidence_with_an_empty_query_is_rejected() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "EVIDADM4").await;
    let candidate_id = create_candidate(&app, &token, "RC-EVIDENCE-003").await;

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/candidates/{candidate_id}/evidence/collect"),
            &token,
            json!({ "query": "   " }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
