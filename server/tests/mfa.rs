use anatolia_bis_server::{db, db::AppState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration as ChronoDuration, Utc};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use totp_rs::{Builder, Secret};
use tower::ServiceExt;

// Multiple tests below set process-wide ADMIN_* env vars for admin seeding;
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

fn auth_json_request(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Computes the current TOTP code for a base32 secret exactly the way an
/// authenticator app would, so tests can drive the real verification path
/// instead of poking internal state.
fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

/// Overwrites the pending/enabled email-method code with a known value,
/// standing in for "the code the user actually received by email" — email
/// delivery is skipped in tests since `RESEND_API_KEY` is unset, so the raw
/// code the server generated internally never appears in any HTTP response
/// (same rationale as `seed_reset_token` in `tests/password_reset.rs`).
async fn seed_email_mfa_code(state: &AppState, user_id: &str, code: &str) {
    let expires_at = (Utc::now() + ChronoDuration::minutes(10))
        .format("%Y-%m-%dT%H:%M:%.3fZ")
        .to_string();
    db::update_email_mfa_code(&state.backend, user_id, &sha256_hex(code), &expires_at)
        .await
        .unwrap();
}

fn totp_code(secret_b32: &str) -> String {
    let secret = Secret::try_from_base32(secret_b32).unwrap();
    let totp = Builder::new()
        .with_secret(secret)
        .with_account_name("test-account".to_string())
        .build()
        .unwrap();
    totp.generate_current().to_string()
}

async fn register_and_login_operator(app: &axum::Router, user_code: &str) -> (String, String) {
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            json!({
                "firstName": "Ada",
                "lastName": "Operator",
                "nationalId": "12345678901",
                "email": format!("{}@example.test", user_code.to_lowercase()),
                "password": "OperatorPass1!",
                "userCode": user_code,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Approve via a fresh admin so the account can log in.
    std::env::set_var("ADMIN_SEED_TOKEN", format!("seed-{user_code}"));
    std::env::set_var("ADMIN_USER_CODE", format!("{user_code}ADM"));
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var(
        "ADMIN_EMAIL",
        format!("{}-admin@example.test", user_code.to_lowercase()),
    );
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", format!("seed-{user_code}"))
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
            json!({ "userCode": format!("{user_code}ADM"), "password": "AdminPass1!" }),
        ))
        .await
        .unwrap();
    let admin_login = body_json(response).await;
    let admin_token = admin_login["accessToken"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(auth_json_request(
            "GET",
            "/api/v1/admin/users",
            &admin_token,
            json!({}),
        ))
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

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": user_code, "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    let login = body_json(response).await;
    let token = login["accessToken"].as_str().unwrap().to_string();
    (token, user_id)
}

#[tokio::test]
async fn voluntary_enrollment_then_login_requires_totp_code() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());
    let (token, _user_id) = register_and_login_operator(&app, "MFAVOL").await;

    // Start enrollment.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/mfa/enroll")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let enroll = body_json(response).await;
    let secret = enroll["secret"].as_str().unwrap().to_string();
    assert!(enroll["otpauthUrl"]
        .as_str()
        .unwrap()
        .starts_with("otpauth://"));

    // Wrong code is rejected.
    let response = app
        .clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/enroll/confirm",
            &token,
            json!({ "code": "000000" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Correct code confirms enrollment and returns recovery codes.
    let response = app
        .clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/enroll/confirm",
            &token,
            json!({ "code": totp_code(&secret) }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let confirm = body_json(response).await;
    let recovery_codes = confirm["recoveryCodes"].as_array().unwrap().clone();
    assert_eq!(recovery_codes.len(), 10);

    // A plain login no longer issues a session directly.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MFAVOL", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let login = body_json(response).await;
    assert_eq!(login["mfaRequired"], true);
    assert!(login.get("accessToken").is_none());
    let mfa_token = login["mfaToken"].as_str().unwrap().to_string();

    // Wrong TOTP code at the challenge step is rejected.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/mfa/challenge/verify",
            json!({ "mfaToken": mfa_token, "code": "000000" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Correct TOTP code completes login.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/mfa/challenge/verify",
            json!({ "mfaToken": mfa_token, "code": totp_code(&secret) }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let verified = body_json(response).await;
    assert!(verified["accessToken"].as_str().is_some());

    // A recovery code works exactly once.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MFAVOL", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    let login2 = body_json(response).await;
    let mfa_token2 = login2["mfaToken"].as_str().unwrap().to_string();
    let recovery_code = recovery_codes[0].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/mfa/challenge/verify",
            json!({ "mfaToken": mfa_token2.clone(), "code": recovery_code.clone() }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Replaying the same recovery code fails.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MFAVOL", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    let login3 = body_json(response).await;
    let mfa_token3 = login3["mfaToken"].as_str().unwrap().to_string();
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/mfa/challenge/verify",
            json!({ "mfaToken": mfa_token3, "code": recovery_code }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn disabling_mfa_requires_password_and_code_and_restores_plain_login() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());
    let (token, _user_id) = register_and_login_operator(&app, "MFADIS").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/mfa/enroll")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let secret = body_json(response).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    app.clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/enroll/confirm",
            &token,
            json!({ "code": totp_code(&secret) }),
        ))
        .await
        .unwrap();

    // Wrong password is rejected even with a correct code.
    let response = app
        .clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/disable",
            &token,
            json!({ "password": "WrongPassword1!", "code": totp_code(&secret) }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/disable",
            &token,
            json!({ "password": "OperatorPass1!", "code": totp_code(&secret) }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Login is a plain login again.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MFADIS", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    let login = body_json(response).await;
    assert!(login["accessToken"].as_str().is_some());
}

#[tokio::test]
async fn required_role_without_enrollment_cannot_obtain_a_session_until_enrolled() {
    let _guard = ENV_GUARD.lock().await;
    let mut state = AppState::for_tests().await;
    state.mfa_required_roles = std::sync::Arc::new(vec!["SYSTEM_ADMIN".to_string()]);
    let app = routes::router(state.clone());

    std::env::set_var("ADMIN_SEED_TOKEN", "mfa-required-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "MFAREQADMIN");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "mfa-required-admin@example.test");
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "mfa-required-seed-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Correct password, but the account has no MFA yet and its role
    // requires it — no session is issued.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MFAREQADMIN", "password": "AdminPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let login = body_json(response).await;
    assert_eq!(login["mfaEnrollmentRequired"], true);
    assert!(login.get("accessToken").is_none());
    let mfa_token = login["mfaToken"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/mfa/challenge/enroll",
            json!({ "mfaToken": mfa_token.clone() }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let secret = body_json(response).await["secret"]
        .as_str()
        .unwrap()
        .to_string();

    // Completing enrollment finally issues the session.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/mfa/challenge/enroll/confirm",
            json!({ "mfaToken": mfa_token, "code": totp_code(&secret) }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let confirmed = body_json(response).await;
    assert!(confirmed["accessToken"].as_str().is_some());
    assert_eq!(confirmed["recoveryCodes"].as_array().unwrap().len(), 10);

    // Now a plain login is challenged (MFA is enabled), not blocked outright.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MFAREQADMIN", "password": "AdminPass1!" }),
        ))
        .await
        .unwrap();
    let login2 = body_json(response).await;
    assert_eq!(login2["mfaRequired"], true);
}

#[tokio::test]
async fn admin_reset_clears_mfa_so_the_next_login_is_a_plain_challenge_or_enrollment() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());
    let (token, user_id) = register_and_login_operator(&app, "MFARST").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/mfa/enroll")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let secret = body_json(response).await["secret"]
        .as_str()
        .unwrap()
        .to_string();
    app.clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/enroll/confirm",
            &token,
            json!({ "code": totp_code(&secret) }),
        ))
        .await
        .unwrap();

    // Log in as the admin created inside register_and_login_operator to
    // call the reset endpoint.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MFARSTADM", "password": "AdminPass1!" }),
        ))
        .await
        .unwrap();
    let admin_login = body_json(response).await;
    let admin_token = admin_login["accessToken"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{user_id}/mfa-reset"))
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MFARST", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    let login = body_json(response).await;
    assert!(login["accessToken"].as_str().is_some());
}

#[tokio::test]
async fn email_method_enrollment_then_login_requires_emailed_code() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());
    let (token, user_id) = register_and_login_operator(&app, "MFAEML").await;

    // Start email-method enrollment.
    let response = app
        .clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/enroll",
            &token,
            json!({ "method": "email" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let enroll = body_json(response).await;
    assert_eq!(enroll["method"], "email");
    assert!(enroll["emailSentTo"].as_str().unwrap().contains('@'));

    seed_email_mfa_code(&state, &user_id, "123456").await;

    // Wrong code is rejected.
    let response = app
        .clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/enroll/confirm",
            &token,
            json!({ "code": "000000" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Correct code confirms enrollment and returns recovery codes.
    let response = app
        .clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/enroll/confirm",
            &token,
            json!({ "code": "123456" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let confirm = body_json(response).await;
    assert_eq!(confirm["recoveryCodes"].as_array().unwrap().len(), 10);

    // A plain login now reports the email method, not a plain session.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MFAEML", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let login = body_json(response).await;
    assert_eq!(login["mfaRequired"], true);
    assert_eq!(login["method"], "email");
    assert!(login.get("accessToken").is_none());
    let mfa_token = login["mfaToken"].as_str().unwrap().to_string();

    // The login handler auto-sends a fresh code, which is unobservable in
    // this test (no RESEND_API_KEY) — stand in for "the code the user
    // received" the same way enrollment did above.
    seed_email_mfa_code(&state, &user_id, "654321").await;

    // Wrong code at the challenge step is rejected.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/mfa/challenge/verify",
            json!({ "mfaToken": mfa_token.clone(), "code": "000000" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Correct emailed code completes login.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/mfa/challenge/verify",
            json!({ "mfaToken": mfa_token, "code": "654321" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let verified = body_json(response).await;
    assert!(verified["accessToken"].as_str().is_some());
}

#[tokio::test]
async fn email_mfa_resend_endpoints_issue_a_fresh_code() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());
    let (token, user_id) = register_and_login_operator(&app, "MFARSND").await;

    app.clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/enroll",
            &token,
            json!({ "method": "email" }),
        ))
        .await
        .unwrap();

    // Voluntary-flow resend replaces the pending code.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/mfa/enroll/resend")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // The resend replaced the pending code — seed the (new) value that
    // would have been re-emailed and confirm with it.
    seed_email_mfa_code(&state, &user_id, "111111").await;
    let response = app
        .clone()
        .oneshot(auth_json_request(
            "POST",
            "/api/v1/auth/mfa/enroll/confirm",
            &token,
            json!({ "code": "111111" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Once enabled, the login-time request-code endpoint issues a fresh
    // code too, ahead of `challenge_verify`.
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MFARSND", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    let login = body_json(response).await;
    let mfa_token = login["mfaToken"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/mfa/challenge/request-code",
            json!({ "mfaToken": mfa_token.clone() }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    seed_email_mfa_code(&state, &user_id, "222222").await;
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/mfa/challenge/verify",
            json!({ "mfaToken": mfa_token, "code": "222222" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_json(response).await["accessToken"].as_str().is_some());
}
