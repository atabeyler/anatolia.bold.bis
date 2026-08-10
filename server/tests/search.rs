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

fn valid_png_bytes(width: u32, height: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    let img = image::RgbImage::from_pixel(width, height, image::Rgb([120, 130, 140]));
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
        .unwrap();
    buf
}

/// Hand-built `multipart/form-data` body — the test suite has no HTTP
/// client dependency (requests go straight through `tower::ServiceExt`),
/// so this constructs exactly what a browser's `FormData` would send.
struct MultipartRequest {
    boundary: &'static str,
    body: Vec<u8>,
}

impl MultipartRequest {
    fn new() -> Self {
        Self {
            boundary: "----anatolia-test-boundary",
            body: Vec::new(),
        }
    }

    fn text_field(mut self, name: &str, value: &str) -> Self {
        self.body
            .extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
        self.body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        self.body.extend_from_slice(value.as_bytes());
        self.body.extend_from_slice(b"\r\n");
        self
    }

    fn image_field(mut self, name: &str, filename: &str, content_type: &str, bytes: &[u8]) -> Self {
        self.body
            .extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
        self.body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n")
                .as_bytes(),
        );
        self.body.extend_from_slice(bytes);
        self.body.extend_from_slice(b"\r\n");
        self
    }

    fn finish(mut self) -> (String, Vec<u8>) {
        self.body
            .extend_from_slice(format!("--{}--\r\n", self.boundary).as_bytes());
        (
            format!("multipart/form-data; boundary={}", self.boundary),
            self.body,
        )
    }
}

async fn seed_admin_and_login(app: &axum::Router, user_code: &str) -> String {
    std::env::set_var("ADMIN_SEED_TOKEN", "search-test-seed-token");
    std::env::set_var("ADMIN_USER_CODE", user_code);
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "search-admin@example.test");

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "search-test-seed-token")
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

/// Submits a search (async flow, madde 18-19: `POST /api/v1/search/face`
/// returns `202 Accepted` immediately) and polls
/// `GET /api/v1/search/{id}/status` until the background pipeline leaves
/// `queued`/`processing`, returning the final `{ "search": ..., "candidates": [...] }`
/// payload. Bounded to avoid hanging the test suite if something regresses.
async fn submit_search_and_wait(
    app: &axum::Router,
    token: &str,
    case_reference: &str,
    purpose: &str,
) -> Value {
    let (content_type, body) = MultipartRequest::new()
        .text_field("caseReference", case_reference)
        .text_field("purpose", purpose)
        .image_field("image", "probe.png", "image/png", &valid_png_bytes(64, 64))
        .finish();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/search/face")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", content_type)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let accepted = body_json(response).await;
    let search_id = accepted["search"]["id"].as_str().unwrap().to_string();

    for _ in 0..100 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/search/{search_id}/status"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let payload = body_json(response).await;
        let status = payload["search"]["status"].as_str().unwrap_or("");
        if status != "queued" && status != "processing" {
            return payload;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("search {search_id} did not leave queued/processing in time");
}

#[tokio::test]
async fn a_real_search_completes_with_ranked_candidates() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "SEARCHADM1").await;

    let payload = submit_search_and_wait(&app, &token, "CASE-001", "Identity verification").await;
    assert_eq!(payload["search"]["status"], "completed");
    assert!(payload["search"]["completedAt"].is_string());
    assert!(!payload["candidates"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_non_image_upload_is_rejected_with_a_specific_code() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "SEARCHADM2").await;

    let (content_type, body) = MultipartRequest::new()
        .text_field("caseReference", "CASE-002")
        .text_field("purpose", "Identity verification")
        .image_field("image", "probe.txt", "text/plain", b"this is not an image")
        .finish();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/search/face")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", content_type)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = body_json(response).await;
    assert_eq!(error["code"], "UNSUPPORTED_IMAGE_TYPE");
}

#[tokio::test]
async fn coordinates_must_come_in_a_valid_pair() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "SEARCHADM3").await;

    // Latitude without longitude.
    let (content_type, body) = MultipartRequest::new()
        .text_field("caseReference", "CASE-003")
        .text_field("purpose", "Identity verification")
        .text_field("latitude", "41.0082")
        .image_field("image", "probe.png", "image/png", &valid_png_bytes(64, 64))
        .finish();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/search/face")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", content_type)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = body_json(response).await;
    assert_eq!(error["messageKey"], "errors.invalidCoordinates");

    // Out-of-range latitude.
    let (content_type, body) = MultipartRequest::new()
        .text_field("caseReference", "CASE-003")
        .text_field("purpose", "Identity verification")
        .text_field("latitude", "999")
        .text_field("longitude", "28.9784")
        .image_field("image", "probe.png", "image/png", &valid_png_bytes(64, 64))
        .finish();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/search/face")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", content_type)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = body_json(response).await;
    assert_eq!(error["messageKey"], "errors.invalidCoordinates");
}

#[tokio::test]
async fn requested_top_k_is_clamped_to_the_configured_maximum() {
    // AppState::for_tests() fixes search_limits at { default: 10, max: 50 }
    // rather than reading SEARCH_MAX_TOP_K/SEARCH_DEFAULT_TOP_K from the
    // environment (that only happens in Config::from_env, used by
    // AppState::new) — so the clamp under test here is against that fixed
    // ceiling of 50, not an env var.
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "SEARCHADM4").await;

    let (content_type, body) = MultipartRequest::new()
        .text_field("caseReference", "CASE-004")
        .text_field("purpose", "Identity verification")
        .text_field("topK", "1000")
        .image_field("image", "probe.png", "image/png", &valid_png_bytes(64, 64))
        .finish();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/search/face")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", content_type)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let payload = body_json(response).await;
    let top_k = payload["search"]["topK"].as_i64().unwrap();
    assert!(
        top_k <= 50,
        "requested topK=1000 must be clamped down, got {top_k}"
    );
}

#[tokio::test]
async fn review_decisions_are_recorded_as_immutable_history() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "SEARCHADM5").await;

    let payload = submit_search_and_wait(&app, &token, "CASE-005", "Identity verification").await;
    let search_id = payload["search"]["id"].as_str().unwrap().to_string();
    let candidate_id = payload["candidates"][0]["candidateId"]
        .as_str()
        .unwrap()
        .to_string();

    // First decision: confirm.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/candidates/{candidate_id}/verify"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "searchId": search_id, "reason": "clear match" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Second decision on the same candidate: reject (e.g. corrected by a
    // second reviewer) — must not erase the first decision.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/candidates/{candidate_id}/reject"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "searchId": search_id, "reason": "corrected" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/search/{search_id}/candidates/{candidate_id}/history"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let history = body_json(response).await;
    let events = history.as_array().unwrap();
    assert_eq!(
        events.len(),
        2,
        "both decisions must be preserved, not just the latest"
    );
    assert_eq!(events[0]["decision"], "confirmed");
    assert_eq!(events[0]["reason"], "clear match");
    assert_eq!(events[1]["decision"], "rejected");
    assert_eq!(events[1]["reason"], "corrected");
}

#[tokio::test]
async fn marking_a_candidate_inconclusive_leaves_it_open_for_further_review() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "SEARCHADM8").await;

    let payload = submit_search_and_wait(&app, &token, "CASE-008", "Identity verification").await;
    let search_id = payload["search"]["id"].as_str().unwrap().to_string();
    let candidate_id = payload["candidates"][0]["candidateId"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/candidates/{candidate_id}/inconclusive"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "searchId": search_id, "reason": "image too low quality" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let candidate = body_json(response).await;
    assert_eq!(candidate["status"], "inconclusive");

    // Unlike confirmed/rejected, inconclusive still allows a later, more
    // confident decision on the same candidate.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/candidates/{candidate_id}/verify"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "searchId": search_id }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let candidate = body_json(response).await;
    assert_eq!(candidate["status"], "confirmed");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/search/{search_id}/candidates/{candidate_id}/history"
                ))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let history = body_json(response).await;
    let events = history.as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["decision"], "inconclusive");
    assert_eq!(events[1]["decision"], "confirmed");
}

#[tokio::test]
async fn search_history_is_paginated_server_side() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "SEARCHADM6").await;

    for i in 0..3 {
        submit_search_and_wait(
            &app,
            &token,
            &format!("CASE-PAGE-{i}"),
            "Identity verification",
        )
        .await;
    }

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/search?page=1&pageSize=2")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    assert_eq!(payload["items"].as_array().unwrap().len(), 2);
    assert_eq!(payload["pageSize"], 2);
    assert!(payload["total"].as_i64().unwrap() >= 3);
}

#[tokio::test]
async fn a_queued_search_is_accepted_immediately_with_a_job_id() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "SEARCHADM9").await;

    let (content_type, body) = MultipartRequest::new()
        .text_field("caseReference", "CASE-009")
        .text_field("purpose", "Identity verification")
        .image_field("image", "probe.png", "image/png", &valid_png_bytes(64, 64))
        .finish();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/search/face")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", content_type)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let payload = body_json(response).await;
    assert!(payload["search"]["id"].as_str().is_some());
    // Accepted immediately means the pipeline hasn't necessarily run yet —
    // the status must be queued or (if the background task already won
    // the race) processing/completed, never something invalid.
    let status = payload["search"]["status"].as_str().unwrap();
    assert!(["queued", "processing", "completed"].contains(&status));
}
