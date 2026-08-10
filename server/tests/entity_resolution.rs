//! Conservative entity resolution (`GET
//! /api/v1/candidates/{id}/possible-duplicates`): advisory-only similarity
//! surfacing over non-biometric signals. See `src/entity_resolution.rs`
//! for the Jaro-Winkler name-similarity unit tests; these exercise the
//! endpoint wiring end to end.

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
    std::env::set_var("ADMIN_SEED_TOKEN", "entity-res-test-seed-token");
    std::env::set_var("ADMIN_USER_CODE", user_code);
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "entity-res-admin@example.test");

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "entity-res-test-seed-token")
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

async fn create_candidate(
    app: &axum::Router,
    token: &str,
    reference_code: &str,
    full_name: &str,
) -> String {
    let created = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/candidates",
            token,
            json!({ "referenceCode": reference_code, "fullName": full_name }),
        ))
        .await
        .unwrap();
    body_json(created).await["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn near_identical_names_are_surfaced_as_possible_duplicates() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "ENTRESADM1").await;

    let first_id = create_candidate(&app, &token, "RC-ENTRES-001", "Jonathan Smith").await;
    create_candidate(&app, &token, "RC-ENTRES-002", "Jonathon Smith").await;
    create_candidate(&app, &token, "RC-ENTRES-003", "Completely Different Person").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/candidates/{first_id}/possible-duplicates"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    let items = payload["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["referenceCode"], "RC-ENTRES-002");
    assert!(items[0]["nameSimilarity"].as_f64().unwrap() >= 0.90);
    assert_eq!(items[0]["matchedSignals"], json!(["name_similarity"]));
}

#[tokio::test]
async fn candidates_sharing_an_alias_are_surfaced_even_with_dissimilar_names() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "ENTRESADM3").await;

    let first_id = create_candidate(&app, &token, "RC-ENTRES-005", "Alpha Person").await;
    let second_id = create_candidate(&app, &token, "RC-ENTRES-006", "Totally Unrelated Name").await;
    create_candidate(&app, &token, "RC-ENTRES-007", "Another Unrelated Name").await;

    // Item 9 in docs/HARDENING_CHECKLIST.md: a shared entity-graph
    // relation (alias, username, or organization) is its own resolution
    // signal, independent of name similarity.
    for id in [&first_id, &second_id] {
        let response = app
            .clone()
            .oneshot(json_request(
                "POST",
                &format!("/api/v1/candidates/{id}/entity-graph"),
                &token,
                json!({ "relationType": "alias", "value": "Shared Alias Name" }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/candidates/{first_id}/possible-duplicates"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    let items = payload["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["referenceCode"], "RC-ENTRES-006");
    assert_eq!(items[0]["matchedSignals"], json!(["shared_alias"]));
}

#[tokio::test]
async fn a_candidate_with_no_similar_names_has_no_matches() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "ENTRESADM2").await;

    let id = create_candidate(&app, &token, "RC-ENTRES-004", "Unique Name Here").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/candidates/{id}/possible-duplicates"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    assert!(payload["items"].as_array().unwrap().is_empty());
}
