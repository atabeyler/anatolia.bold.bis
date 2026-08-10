//! `POST /api/v1/admin/users/:id/role` (madde 11): changing a user's role
//! must take effect immediately, not just for future logins — a session
//! issued under the old role must stop working the moment the role
//! changes, whether that's a promotion or a demotion.

use anatolia_bis_server::{db::AppState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tower::ServiceExt;

// Every test here sets process-wide ADMIN_* env vars; serialize them so
// they don't race under cargo test's default parallel execution within
// this binary (see tests/admin_hardening.rs for the same pattern).
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

fn refresh_cookie(response: &axum::response::Response) -> String {
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}

async fn seed_admin(app: &axum::Router, seed_token: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", seed_token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn login(app: &axum::Router, user_code: &str, password: &str) -> axum::response::Response {
    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": user_code, "password": password }),
        ))
        .await
        .unwrap()
}

async fn register_and_approve(
    app: &axum::Router,
    admin_token: &str,
    user_code: &str,
    password: &str,
    national_id: &str,
) -> String {
    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            json!({
                "firstName": "Role",
                "lastName": "Target",
                "nationalId": national_id,
                "email": format!("{}@example.test", user_code.to_lowercase()),
                "password": password,
                "userCode": user_code,
            }),
        ))
        .await
        .unwrap();

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
    let user_id = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["userCode"] == user_code)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
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
    assert_eq!(response.status(), StatusCode::OK);

    user_id
}

async fn change_role(
    app: &axum::Router,
    admin_token: &str,
    user_id: &str,
    role: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/role"))
                .header("authorization", format!("Bearer {admin_token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "role": role }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn changing_a_users_role_revokes_their_existing_session() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("BOOTSTRAP_ENABLED");
    std::env::set_var("ADMIN_SEED_TOKEN", "role-change-seed-token-1");
    std::env::set_var("ADMIN_USER_CODE", "ROLEADM1");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "role-admin-1@example.test");

    let state = AppState::for_tests().await;
    let app = routes::router(state);
    assert_eq!(
        seed_admin(&app, "role-change-seed-token-1").await,
        StatusCode::OK
    );
    let admin_login = login(&app, "ROLEADM1", "AdminPass1!").await;
    let admin_token = body_json(admin_login)
        .await
        .get("accessToken")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let target_id = register_and_approve(
        &app,
        &admin_token,
        "ROLEUSR1",
        "TargetPass1!",
        "11122233301",
    )
    .await;

    // The target logs in as OPERATOR (the default approved role) and gets
    // a working refresh session.
    let target_login = login(&app, "ROLEUSR1", "TargetPass1!").await;
    assert_eq!(target_login.status(), StatusCode::OK);
    let cookie = refresh_cookie(&target_login);

    let refresh_before = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_before.status(), StatusCode::OK);
    // Refresh rotates the cookie; use the freshest one for the next check.
    let cookie = refresh_cookie(&refresh_before);

    let change_response = change_role(&app, &admin_token, &target_id, "REVIEWER").await;
    assert_eq!(change_response.status(), StatusCode::OK);

    let refresh_after = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_after.status(), StatusCode::UNAUTHORIZED);

    // A fresh login picks up the new role.
    let response = login(&app, "ROLEUSR1", "TargetPass1!").await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn assigning_an_unknown_role_is_rejected() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("BOOTSTRAP_ENABLED");
    std::env::set_var("ADMIN_SEED_TOKEN", "role-change-seed-token-2");
    std::env::set_var("ADMIN_USER_CODE", "ROLEADM2");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "role-admin-2@example.test");

    let state = AppState::for_tests().await;
    let app = routes::router(state);
    assert_eq!(
        seed_admin(&app, "role-change-seed-token-2").await,
        StatusCode::OK
    );
    let admin_login = login(&app, "ROLEADM2", "AdminPass1!").await;
    let admin_token = body_json(admin_login)
        .await
        .get("accessToken")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    let target_id = register_and_approve(
        &app,
        &admin_token,
        "ROLEUSR2",
        "TargetPass1!",
        "11122233302",
    )
    .await;

    let response = change_role(&app, &admin_token, &target_id, "NOT_A_ROLE").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = change_role(&app, &admin_token, &target_id, "pending").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn demoting_the_last_active_admin_is_refused() {
    let _guard = ENV_GUARD.lock().await;
    std::env::remove_var("BOOTSTRAP_ENABLED");
    std::env::set_var("ADMIN_SEED_TOKEN", "role-change-seed-token-3");
    std::env::set_var("ADMIN_USER_CODE", "ROLEADM3");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "role-admin-3@example.test");

    let state = AppState::for_tests().await;
    let app = routes::router(state);
    assert_eq!(
        seed_admin(&app, "role-change-seed-token-3").await,
        StatusCode::OK
    );
    let admin_login = login(&app, "ROLEADM3", "AdminPass1!").await;
    let admin_token = body_json(admin_login)
        .await
        .get("accessToken")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

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
    let admin_id = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["userCode"] == "ROLEADM3")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let response = change_role(&app, &admin_token, &admin_id, "SECURITY_ADMIN").await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let error = body_json(response).await;
    assert_eq!(error["code"], "LAST_ADMIN_PROTECTED");

    // Still an admin, unaffected.
    let response = login(&app, "ROLEADM3", "AdminPass1!").await;
    assert_eq!(response.status(), StatusCode::OK);
}
