use anatolia_bis_server::{db::AppState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tower::ServiceExt;

// ADMIN_SEED_TOKEN/ADMIN_USER_CODE/ADMIN_PASSWORD/ADMIN_EMAIL are
// process-wide env vars (see tests/auth.rs); serialize the tests in this
// file so setting them for one seed-admin call can't race another test's
// concurrent write to the same vars.
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

/// Bootstraps a fresh admin account, logs in, and returns its access
/// token — a login by itself already generates at least one
/// AUTH_LOGIN_SUCCESS audit event, which the tests below rely on.
async fn seed_and_login_admin(app: &axum::Router, user_code: &str) -> String {
    std::env::set_var("ADMIN_SEED_TOKEN", "audit-test-seed-token");
    std::env::set_var("ADMIN_USER_CODE", user_code);
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "audit-admin@example.test");

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "audit-test-seed-token")
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
            json!({ "userCode": user_code, "password": "AdminPass1!" }),
        ))
        .await
        .unwrap();
    body_json(response).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn audit_endpoint_requires_a_privileged_role() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    // No token at all.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // An OPERATOR (self-registered, admin-approved) is not privileged
    // enough to read the audit trail.
    let admin_token = seed_and_login_admin(&app, "AUDITADM1").await;

    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            json!({
                "firstName": "Op",
                "lastName": "Erator",
                "nationalId": "55566677788",
                "email": "operator@example.test",
                "password": "OperatorPass1!",
                "userCode": "AUDITOP1",
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
    let operator_id = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["userCode"] == "AUDITOP1")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{operator_id}/approve"))
                .header("authorization", format!("Bearer {admin_token}"))
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
            json!({ "userCode": "AUDITOP1", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    let operator_token = body_json(response).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit")
                .header("authorization", format!("Bearer {operator_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // SYSTEM_ADMIN (the seeded admin) can read it.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_and_registration_generate_audit_events_visible_through_the_endpoint() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let admin_token = seed_and_login_admin(&app, "AUDITADM2").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit?action=AUTH_LOGIN_SUCCESS")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    let items = payload["items"].as_array().unwrap();
    assert!(
        !items.is_empty(),
        "expected at least the admin's own login to be recorded"
    );
    assert!(items
        .iter()
        .all(|item| item["action"] == "AUTH_LOGIN_SUCCESS"));
    assert!(items[0]["actorUserCode"] == "AUDITADM2");
    assert!(payload["total"].as_i64().unwrap() >= 1);

    // A failed login (wrong password) is also recorded, with the right
    // action/result — not silently dropped.
    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "AUDITADM2", "password": "WrongPassword1!" }),
        ))
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit?action=AUTH_LOGIN_FAILED")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let payload = body_json(response).await;
    assert!(!payload["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn audit_page_size_is_clamped_to_the_max() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let admin_token = seed_and_login_admin(&app, "AUDITADM3").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit?pageSize=99999")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    assert_eq!(payload["pageSize"].as_i64().unwrap(), 200);
}
