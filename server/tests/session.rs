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

/// Pulls the raw `refresh_token=...` value out of a `Set-Cookie` header,
/// ignoring the `Path=`/`HttpOnly`/`SameSite=`/... attributes that follow.
fn refresh_cookie(response: &axum::response::Response) -> String {
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}

/// A deterministic, distinct-per-user_code 11-digit national ID — a test
/// that registers more than one account in the same run (e.g. a victim
/// and an attacker) needs each to be unique, since a shared fixed value
/// would collide on the second registration.
fn national_id_for(user_code: &str) -> String {
    let sum: u32 = user_code.bytes().map(u32::from).sum();
    format!("9876543{:04}", sum % 10000)
}

async fn approve_and_login(
    app: &axum::Router,
    user_code: &str,
    password: &str,
) -> axum::response::Response {
    std::env::set_var("ADMIN_SEED_TOKEN", "session-test-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "SESSADMIN");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "sessadmin@example.test");

    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            json!({
                "firstName": "Session",
                "lastName": "Tester",
                "nationalId": national_id_for(user_code),
                "email": format!("{}@example.test", user_code.to_lowercase()),
                "password": password,
                "userCode": user_code,
            }),
        ))
        .await
        .unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "session-test-seed-token")
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
            json!({ "userCode": "SESSADMIN", "password": "AdminPass1!" }),
        ))
        .await
        .unwrap();
    let login = body_json(response).await;
    let admin_token = login["accessToken"].as_str().unwrap().to_string();

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

    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": user_code, "password": password }),
        ))
        .await
        .unwrap()
}

#[tokio::test]
async fn refresh_rotates_the_cookie_and_old_one_stops_working() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let login_response = approve_and_login(&app, "ROTATE01", "RotatePass1!").await;
    assert_eq!(login_response.status(), StatusCode::OK);
    let first_cookie = refresh_cookie(&login_response);

    // First refresh succeeds and rotates to a new cookie.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("cookie", &first_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let second_cookie = refresh_cookie(&response);
    assert_ne!(
        first_cookie, second_cookie,
        "refresh must rotate to a new token"
    );

    // Reusing the now-stale first cookie is rejected, and — because reuse
    // revokes the whole family — the second (legitimately rotated-to)
    // cookie is rejected too.
    let reuse_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("cookie", &first_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reuse_response.status(), StatusCode::UNAUTHORIZED);

    let after_reuse_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("cookie", &second_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        after_reuse_response.status(),
        StatusCode::UNAUTHORIZED,
        "refresh-token reuse must revoke the entire token family, not just the reused token"
    );
}

#[tokio::test]
async fn logout_revokes_the_session_so_refresh_stops_working() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let login_response = approve_and_login(&app, "LOGOUT01", "LogoutPass1!").await;
    let cookie = refresh_cookie(&login_response);

    let logout_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_response.status(), StatusCode::OK);

    let refresh_response = app
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
    assert_eq!(refresh_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_all_revokes_every_session_for_the_user() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    // Two independent "devices" logging in as the same account.
    let first_login = approve_and_login(&app, "MULTI01", "MultiPass1!").await;
    let first_cookie = refresh_cookie(&first_login);

    let second_login = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "MULTI01", "password": "MultiPass1!" }),
        ))
        .await
        .unwrap();
    let access_token = body_json(second_login).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    let logout_all_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout-all")
                .header("authorization", format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_all_response.status(), StatusCode::OK);

    let refresh_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("cookie", &first_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        refresh_response.status(),
        StatusCode::UNAUTHORIZED,
        "logout-all must revoke sessions created before it ran, not just the caller's own"
    );
}

#[tokio::test]
async fn listing_sessions_shows_every_active_device_and_marks_the_current_one() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let first_login = approve_and_login(&app, "DEVLIST1", "DevListPass1!").await;
    let first_cookie = refresh_cookie(&first_login);
    let first_access_token = body_json(first_login).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    let second_login = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "DEVLIST1", "password": "DevListPass1!" }),
        ))
        .await
        .unwrap();
    assert_eq!(second_login.status(), StatusCode::OK);

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/users/me/sessions")
                .header("authorization", format!("Bearer {first_access_token}"))
                .header("cookie", &first_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_response.status(), StatusCode::OK);
    let payload = body_json(list_response).await;
    let items = payload["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        2,
        "both logins should be listed as active sessions"
    );
    let current_count = items.iter().filter(|s| s["isCurrent"] == true).count();
    assert_eq!(
        current_count, 1,
        "exactly the session behind the request's own refresh cookie should be marked current"
    );
}

#[tokio::test]
async fn a_users_own_session_can_be_individually_revoked() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let first_login = approve_and_login(&app, "DEVREV01", "DevRevPass1!").await;
    let first_cookie = refresh_cookie(&first_login);
    let first_access_token = body_json(first_login).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    let second_login = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "DEVREV01", "password": "DevRevPass1!" }),
        ))
        .await
        .unwrap();
    let second_cookie = refresh_cookie(&second_login);

    let list_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/users/me/sessions")
                .header("authorization", format!("Bearer {first_access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let payload = body_json(list_response).await;
    let items = payload["items"].as_array().unwrap();
    let other_session_id = items
        .iter()
        .find(|s| s["isCurrent"] != true)
        .expect("the second login's session should be listed and not marked current from the first device's request")
        ["id"]
        .as_str()
        .unwrap()
        .to_string();

    let revoke_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/users/me/sessions/{other_session_id}"))
                .header("authorization", format!("Bearer {first_access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke_response.status(), StatusCode::OK);

    // The revoked (second) device's refresh cookie stops working...
    let refresh_after_revoke = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("cookie", &second_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_after_revoke.status(), StatusCode::UNAUTHORIZED);

    // ...while the caller's own (first) session is untouched.
    let refresh_first_still_works = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("cookie", &first_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_first_still_works.status(), StatusCode::OK);
}

#[tokio::test]
async fn revoking_another_users_session_id_is_rejected_as_not_found() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let victim_login = approve_and_login(&app, "DEVVICT1", "DevVictPass1!").await;
    let victim_access_token = body_json(victim_login).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();
    let victim_sessions = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/users/me/sessions")
                .header("authorization", format!("Bearer {victim_access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let victim_session_id = body_json(victim_sessions).await["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let attacker_login = approve_and_login(&app, "DEVATTK1", "DevAttkPass1!").await;
    let attacker_access_token = body_json(attacker_login).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/users/me/sessions/{victim_session_id}"))
                .header("authorization", format!("Bearer {attacker_access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn registration_status_is_not_enumerable_by_user_code() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            json!({
                "firstName": "Track",
                "lastName": "Ing",
                "nationalId": "11122233344",
                "email": "tracking@example.test",
                "password": "TrackingPass1!",
                "userCode": "TRACK01",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body_json(response).await;
    let tracking_token = body["registrationTrackingToken"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        tracking_token.len() >= 32,
        "tracking token should be high-entropy, not the user code"
    );

    // Querying by the raw user code (the old, enumerable endpoint's
    // parameter) must not work — the path itself no longer exists.
    let by_user_code = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/auth/registration-status/TRACK01")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = body_json(by_user_code).await;
    assert_eq!(status["status"], "not_found");

    // Querying by the actual tracking token works.
    let by_token = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/auth/registration-status/{tracking_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = body_json(by_token).await;
    assert_eq!(status["status"], "pending");
}
