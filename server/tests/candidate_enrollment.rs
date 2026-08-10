//! Candidate enrollment endpoints (madde 1-6): candidate creation and the
//! reference-photo pipeline. These tests run under the default mock
//! `BiometricProvider` (no network access or real model required in CI),
//! so they exercise the wiring — permission gates, candidate lookup,
//! duplicate-reference-code handling, and the "mock has no real embedding"
//! honesty guarantee — rather than real face-detection behavior. The real
//! YuNet/SFace decode math is covered by unit tests in
//! `src/biometric/{detection,alignment,embedding,quality}.rs`, which don't
//! require network access since they test the math directly rather than
//! running actual model inference.

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

fn valid_png_bytes(width: u32, height: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    let img = image::RgbImage::from_pixel(width, height, image::Rgb([120, 130, 140]));
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
        .unwrap();
    buf
}

async fn seed_admin_and_login(app: &axum::Router, user_code: &str) -> String {
    std::env::set_var("ADMIN_SEED_TOKEN", "enrollment-test-seed-token");
    std::env::set_var("ADMIN_USER_CODE", user_code);
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "enrollment-admin@example.test");

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "enrollment-test-seed-token")
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

#[tokio::test]
async fn creating_a_candidate_succeeds_and_is_auditable() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "ENROLLADM1").await;

    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/candidates",
            &token,
            json!({ "referenceCode": "RC-ENROLL-001", "fullName": "Test Candidate" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    assert_eq!(payload["referenceCode"], "RC-ENROLL-001");
    assert!(payload["id"].as_str().is_some());
}

#[tokio::test]
async fn duplicate_reference_code_is_rejected_with_conflict() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "ENROLLADM2").await;

    let create = || {
        json_request(
            "POST",
            "/api/v1/candidates",
            &token,
            json!({ "referenceCode": "RC-DUPLICATE", "fullName": "First" }),
        )
    };
    let first = app.clone().oneshot(create()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = app.clone().oneshot(create()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn reference_photo_upload_fails_closed_under_the_mock_provider() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "ENROLLADM3").await;

    let created = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/candidates",
            &token,
            json!({ "referenceCode": "RC-MOCK-UPLOAD", "fullName": "Mock Upload" }),
        ))
        .await
        .unwrap();
    let candidate_id = body_json(created).await["id"].as_str().unwrap().to_string();

    let boundary = "----enrollment-test-boundary";
    let png = valid_png_bytes(64, 64);
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"image\"; filename=\"probe.png\"\r\nContent-Type: image/png\r\n\r\n",
    );
    body.extend_from_slice(&png);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/api/v1/candidates/{candidate_id}/reference-photos"
                ))
                .header("authorization", format!("Bearer {token}"))
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    // The default (mock) BiometricProvider has no real embedding to
    // enroll — this must fail honestly (503) rather than silently
    // "succeeding" with a fake template. See
    // `biometric::MockBiometricProvider::enroll`.
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let payload = body_json(response).await;
    assert_eq!(payload["code"], "BIOMETRIC_PROVIDER_UNAVAILABLE");
}

#[tokio::test]
async fn listing_templates_for_a_fresh_candidate_is_empty() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "ENROLLADM4").await;

    let created = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/candidates",
            &token,
            json!({ "referenceCode": "RC-NO-TEMPLATES", "fullName": "No Templates" }),
        ))
        .await
        .unwrap();
    let candidate_id = body_json(created).await["id"].as_str().unwrap().to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/candidates/{candidate_id}/templates"))
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

#[tokio::test]
async fn revoking_a_nonexistent_template_is_not_found() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "ENROLLADM5").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/candidates/some-candidate/templates/nonexistent-template/revoke")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn uploading_a_reference_photo_for_an_unknown_candidate_is_not_found() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "ENROLLADM6").await;

    let boundary = "----enrollment-test-boundary-2";
    let png = valid_png_bytes(64, 64);
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"image\"; filename=\"probe.png\"\r\nContent-Type: image/png\r\n\r\n",
    );
    body.extend_from_slice(&png);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/candidates/does-not-exist/reference-photos")
                .header("authorization", format!("Bearer {token}"))
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
