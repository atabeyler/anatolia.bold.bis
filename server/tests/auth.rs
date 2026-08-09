use anatolia_bis_server::{db::AppState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

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

/// Exercises the full lifecycle in one test (register -> blocked login
/// while pending -> admin seed -> admin approval -> successful login ->
/// authenticated /users/me) rather than splitting it up, since
/// ADMIN_SEED_TOKEN/ADMIN_USER_CODE/ADMIN_PASSWORD/ADMIN_EMAIL are
/// process-wide env vars that would otherwise race across parallel tests.
#[tokio::test]
async fn full_registration_and_admin_approval_flow() {
    std::env::set_var("ADMIN_SEED_TOKEN", "test-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "ADMIN01");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "admin@example.test");

    let state = AppState::for_tests().await;
    let app = routes::router(state);

    // 1. Register a new operator — starts out pending.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            json!({
                "firstName": "Ada",
                "lastName": "Operator",
                "nationalId": "12345678901",
                "email": "ada@example.test",
                "password": "OperatorPass1!",
                "userCode": "OPER01",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // 2. Login before approval is rejected.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "OPER01", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let error = body_json(response).await;
    assert_eq!(error["code"], "FORBIDDEN");
    assert_eq!(error["messageKey"], "errors.accountNotApproved");

    // 3. Seed the first admin account.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "test-seed-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 4. Admin logs in and approves the pending operator.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "ADMIN01", "password": "AdminPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let login = body_json(response).await;
    let admin_token = login["accessToken"].as_str().unwrap().to_string();
    assert_eq!(login["user"]["role"], "SYSTEM_ADMIN");

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
    assert_eq!(response.status(), StatusCode::OK);
    let users = body_json(response).await;
    let pending_user = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["userCode"] == "OPER01")
        .unwrap();
    let operator_id = pending_user["id"].as_str().unwrap().to_string();

    let response = app
        .clone()
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
    assert_eq!(response.status(), StatusCode::OK);

    // 5. Now the operator can log in and access their own profile.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "OPER01", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let login = body_json(response).await;
    let operator_token = login["accessToken"].as_str().unwrap().to_string();
    assert_eq!(login["user"]["role"], "OPERATOR");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/users/me")
                .header("authorization", format!("Bearer {operator_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let me = body_json(response).await;
    assert_eq!(me["userCode"], "OPER01");

    // 6. An unauthenticated request is rejected with the stable error shape.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/users/me")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let error = body_json(response).await;
    assert_eq!(error["code"], "UNAUTHORIZED");
    assert!(error["requestId"].is_string());
}
