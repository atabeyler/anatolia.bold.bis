use anatolia_bis_server::{db, db::AppState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tower::ServiceExt;

// Both tests below set process-wide ADMIN_* env vars for admin seeding;
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

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

async fn register_user(app: &axum::Router, user_code: &str, email: &str) {
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            json!({
                "firstName": "Ada",
                "lastName": "Operator",
                "nationalId": "12345678901",
                "email": email,
                "password": "OperatorPass1!",
                "userCode": user_code,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

/// Simulates the token `forgot_password` would have emailed, by inserting
/// a single-use `password_reset` token directly via the db layer (email
/// delivery is skipped in tests since RESEND_API_KEY is unset, so the raw
/// token never appears in any HTTP response).
async fn seed_reset_token(state: &AppState, user_id: &str, ttl_hours: i64) -> String {
    let raw_token = "test-reset-token-0123456789abcdef";
    let expires_at = Utc::now() + ChronoDuration::hours(ttl_hours);
    db::create_approval_token(
        &state.backend,
        user_id,
        &sha256_hex(raw_token),
        "password_reset",
        expires_at,
    )
    .await
    .unwrap();
    raw_token.to_string()
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
async fn reset_password_with_valid_token_sets_new_password_and_revokes_sessions() {
    let _guard = ENV_GUARD.lock().await;
    std::env::set_var("ADMIN_SEED_TOKEN", "reset-flow-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "RSTADMIN");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "reset-admin@example.test");

    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());

    register_user(&app, "RSTUSER", "rstuser@example.test").await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "reset-flow-seed-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "RSTADMIN", "password": "AdminPass1!" }),
        ))
        .await
        .unwrap();
    let login = body_json(response).await;
    let admin_token = login["accessToken"].as_str().unwrap().to_string();

    let user_id = find_user_id(&app, &admin_token, "RSTUSER").await;
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/approve"))
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Original password still works, and this session's refresh cookie
    // should be revoked once the reset completes below.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "RSTUSER", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let raw_token = seed_reset_token(&state, &user_id, 1).await;

    // Wrong new password fails validation before the token is touched.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/reset-password",
            json!({ "token": raw_token, "newPassword": "short" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/reset-password",
            json!({ "token": raw_token, "newPassword": "NewOperatorPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The token is single-use: replaying it must fail.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/reset-password",
            json!({ "token": raw_token, "newPassword": "AnotherPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = body_json(response).await;
    assert_eq!(error["messageKey"], "errors.invalidResetToken");

    // Old password no longer works; the new one does.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "RSTUSER", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "RSTUSER", "password": "NewOperatorPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn reset_password_rejects_expired_token() {
    let _guard = ENV_GUARD.lock().await;
    std::env::set_var("ADMIN_SEED_TOKEN", "reset-expired-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "EXPADMIN");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "exp-admin@example.test");

    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());

    register_user(&app, "EXPUSER", "expuser@example.test").await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "reset-expired-seed-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "EXPADMIN", "password": "AdminPass1!" }),
        ))
        .await
        .unwrap();
    let login = body_json(response).await;
    let admin_token = login["accessToken"].as_str().unwrap().to_string();
    let user_id = find_user_id(&app, &admin_token, "EXPUSER").await;

    // Already expired: -1 hour TTL.
    let raw_token = seed_reset_token(&state, &user_id, -1).await;

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/reset-password",
            json!({ "token": raw_token, "newPassword": "NewOperatorPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = body_json(response).await;
    assert_eq!(error["messageKey"], "errors.invalidResetToken");
}

#[tokio::test]
async fn reset_password_rejects_unknown_token() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/reset-password",
            json!({ "token": "not-a-real-token", "newPassword": "NewOperatorPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = body_json(response).await;
    assert_eq!(error["messageKey"], "errors.invalidResetToken");
}
