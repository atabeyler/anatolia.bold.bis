//! `GET /api/v1/admin/connectors`: admin-only, read-only visibility into
//! which OSINT connector is active
//! in each provider slot.

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

#[tokio::test]
async fn admin_can_list_connector_status_and_others_cannot() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());

    std::env::set_var("ADMIN_SEED_TOKEN", "connectors-test-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "CONNADMIN");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "connectors-admin@example.test");
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "connectors-test-seed-token")
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
                    json!({ "userCode": "CONNADMIN", "password": "AdminPass1!" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let admin_token = body_json(response).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/connectors")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    let items = payload["items"].as_array().unwrap();
    // AppState::for_tests() always wires the mock orchestrator (no API
    // keys set in the test environment), so every slot should report
    // its mock provider — a real assertion on this test's actual state,
    // not just "the endpoint responds".
    assert_eq!(items.len(), 3, "web_search, news, and social slots");
    for item in items {
        assert_eq!(item["isMock"], true);
        assert!(item["providerName"].as_str().unwrap().starts_with("mock-"));
    }
    let slots: Vec<&str> = items.iter().map(|i| i["slot"].as_str().unwrap()).collect();
    assert!(slots.contains(&"web_search"));
    assert!(slots.contains(&"news"));
    assert!(slots.contains(&"social"));

    // No auth at all — must not leak connector configuration.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/connectors")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
