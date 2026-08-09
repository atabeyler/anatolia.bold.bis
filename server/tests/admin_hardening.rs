use anatolia_bis_server::{db::AppState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tower::ServiceExt;

// Every test here sets process-wide ADMIN_* / BOOTSTRAP_ENABLED env vars;
// serialize them so they don't race under cargo test's default parallel
// execution within this binary (see tests/search.rs for the same pattern).
static ENV_GUARD: Mutex<()> = Mutex::const_new(());

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn seed_admin(app: &axum::Router, seed_token: &str) -> StatusCode {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", seed_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    response.status()
}

async fn login(app: &axum::Router, user_code: &str, password: &str) -> String {
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": user_code, "password": password }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn find_user_id(app: &axum::Router, admin_token: &str, user_code: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let users = body_json(response).await;
    users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["userCode"] == user_code)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn seed_admin_disables_itself_once_an_admin_already_exists() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("BOOTSTRAP_ENABLED");
    std::env::set_var("ADMIN_SEED_TOKEN", "self-disable-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "SDADMIN1");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "sd-admin1@example.test");

    let state = AppState::for_tests().await;
    let app = routes::router(state);

    assert_eq!(
        seed_admin(&app, "self-disable-seed-token").await,
        StatusCode::OK
    );

    // A second bootstrap attempt, even with a different admin identity,
    // must be refused now that an active SYSTEM_ADMIN exists.
    std::env::set_var("ADMIN_USER_CODE", "SDADMIN2");
    std::env::set_var("ADMIN_EMAIL", "sd-admin2@example.test");
    assert_eq!(
        seed_admin(&app, "self-disable-seed-token").await,
        StatusCode::FORBIDDEN
    );

    // Explicit override re-opens it for a deliberate recovery.
    std::env::set_var("BOOTSTRAP_ENABLED", "true");
    assert_eq!(
        seed_admin(&app, "self-disable-seed-token").await,
        StatusCode::OK
    );
    std::env::remove_var("BOOTSTRAP_ENABLED");
}

#[tokio::test]
async fn banning_the_last_active_admin_is_refused() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("BOOTSTRAP_ENABLED");
    std::env::set_var("ADMIN_SEED_TOKEN", "last-admin-ban-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "LASTADM1");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "last-admin-ban@example.test");

    let state = AppState::for_tests().await;
    let app = routes::router(state);
    assert_eq!(
        seed_admin(&app, "last-admin-ban-seed-token").await,
        StatusCode::OK
    );

    let admin_token = login(&app, "LASTADM1", "AdminPass1!").await;
    let admin_id = find_user_id(&app, &admin_token, "LASTADM1").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{admin_id}/ban"))
                .header("authorization", format!("Bearer {admin_token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let error = body_json(response).await;
    assert_eq!(error["code"], "LAST_ADMIN_PROTECTED");

    // Still able to log in — the ban never took effect.
    login(&app, "LASTADM1", "AdminPass1!").await;
}

#[tokio::test]
async fn deleting_the_last_active_admin_is_refused_but_a_second_admin_can_be() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("BOOTSTRAP_ENABLED");
    std::env::set_var("ADMIN_SEED_TOKEN", "last-admin-delete-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "DELADM1");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "last-admin-delete@example.test");

    let state = AppState::for_tests().await;
    let app = routes::router(state);
    assert_eq!(
        seed_admin(&app, "last-admin-delete-seed-token").await,
        StatusCode::OK
    );

    let admin_token = login(&app, "DELADM1", "AdminPass1!").await;
    let admin_id = find_user_id(&app, &admin_token, "DELADM1").await;

    // Create a second admin directly, so a delete of it is not
    // last-admin-protected.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {admin_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "userCode": "DELADM2",
                        "password": "AdminPass2!",
                        "nationalId": "12345678901",
                        "email": "second-admin@example.test",
                        "isAdmin": true,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let second_admin_id = find_user_id(&app, &admin_token, "DELADM2").await;

    // Deleting the second admin (while the first is still active) succeeds.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{second_admin_id}"))
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Now only one admin remains — deleting it must be refused.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{admin_id}"))
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let error = body_json(response).await;
    assert_eq!(error["code"], "LAST_ADMIN_PROTECTED");
}

#[tokio::test]
async fn readiness_endpoint_reports_ready_when_the_database_is_reachable() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["status"], "ready");
}

#[tokio::test]
async fn deleting_a_user_soft_deletes_and_they_disappear_from_login_and_listing() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("BOOTSTRAP_ENABLED");
    std::env::set_var("ADMIN_SEED_TOKEN", "soft-delete-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "SOFTADM1");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "soft-delete-admin@example.test");

    let state = AppState::for_tests().await;
    let app = routes::router(state);
    assert_eq!(
        seed_admin(&app, "soft-delete-seed-token").await,
        StatusCode::OK
    );
    let admin_token = login(&app, "SOFTADM1", "AdminPass1!").await;

    // A second, non-admin user to delete.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {admin_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "userCode": "SOFTUSR1",
                        "password": "UserPass1!",
                        "nationalId": "98765432109",
                        "email": "soft-delete-user@example.test",
                        "isAdmin": false,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let target_id = find_user_id(&app, &admin_token, "SOFTUSR1").await;

    login(&app, "SOFTUSR1", "UserPass1!").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{target_id}"))
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Deleted user can no longer log in.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "SOFTUSR1", "password": "UserPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Deleted user no longer appears in the admin listing.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/users")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let users = body_json(response).await;
    assert!(!users["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["userCode"] == "SOFTUSR1"));

    // Deleting the same (already-deleted) user again is a harmless no-op,
    // not a 404 — it is still, correctly, no longer a live account.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/admin/users/{target_id}"))
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // A genuinely unknown id still 404s.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/admin/users/00000000-0000-0000-0000-000000000000")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
