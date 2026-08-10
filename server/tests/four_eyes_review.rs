//! Four-eyes / second-review policy (madde 15): when
//! `AppState::require_second_review` is `true`, a candidate's first
//! confirm/reject decision only moves it to `needs_second_review`; a
//! second, different reviewer's decision is what actually finalizes it.
//! See `db::record_review_decision`.

use anatolia_bis_server::{db, db::AppState, roles, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use bcrypt::hash;
use http_body_util::BodyExt;
use image::{DynamicImage, ImageFormat, RgbImage};
use serde_json::{json, Value};
use std::io::Cursor;
use tower::ServiceExt;

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn valid_png_bytes() -> Vec<u8> {
    let mut buf = Vec::new();
    let img = RgbImage::from_pixel(64, 64, image::Rgb([120, 130, 140]));
    DynamicImage::ImageRgb8(img)
        .write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
        .unwrap();
    buf
}

struct MultipartRequest {
    boundary: &'static str,
    body: Vec<u8>,
}

impl MultipartRequest {
    fn new() -> Self {
        Self {
            boundary: "----four-eyes-test-boundary",
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

    fn image_field(mut self, bytes: &[u8]) -> Self {
        self.body
            .extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
        self.body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"image\"; filename=\"probe.png\"\r\nContent-Type: image/png\r\n\r\n",
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

async fn create_reviewer(state: &AppState, user_code: &str) -> String {
    db::create_user(
        &state.backend,
        user_code,
        Some(&format!("{}@example.test", user_code.to_lowercase())),
        "Reviewer",
        "Tester",
        None,
        None,
        &hash("ReviewerPass1!", bcrypt::DEFAULT_COST).unwrap(),
        roles::REVIEWER,
        true,
    )
    .await
    .unwrap();
    user_code.to_string()
}

async fn login(app: &axum::Router, user_code: &str, password: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "userCode": user_code, "password": password }).to_string(),
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

async fn create_search(app: &axum::Router, token: &str, case_reference: &str) -> (String, String) {
    let (content_type, body) = MultipartRequest::new()
        .text_field("caseReference", case_reference)
        .text_field("purpose", "Identity verification")
        .image_field(&valid_png_bytes())
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
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    let search_id = payload["search"]["id"].as_str().unwrap().to_string();
    let candidate_id = payload["candidates"][0]["candidateId"]
        .as_str()
        .unwrap()
        .to_string();
    (search_id, candidate_id)
}

async fn review(
    app: &axum::Router,
    token: &str,
    action: &str,
    candidate_id: &str,
    search_id: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/candidates/{candidate_id}/{action}"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "searchId": search_id }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn state_with_second_review_required() -> AppState {
    let mut state = AppState::for_tests().await;
    state.require_second_review = true;
    state
}

#[tokio::test]
async fn first_decision_moves_candidate_to_needs_second_review_not_final() {
    let state = state_with_second_review_required().await;
    let app = routes::router(state.clone());
    create_reviewer(&state, "FE1REV1").await;
    let token = login(&app, "FE1REV1", "ReviewerPass1!").await;
    let (search_id, candidate_id) = create_search(&app, &token, "FE-CASE-1").await;

    let response = review(&app, &token, "verify", &candidate_id, &search_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    let candidate = body_json(response).await;
    assert_eq!(candidate["status"], "needs_second_review");
}

#[tokio::test]
async fn same_reviewer_cannot_provide_the_second_decision() {
    let state = state_with_second_review_required().await;
    let app = routes::router(state.clone());
    create_reviewer(&state, "FE2REV1").await;
    let token = login(&app, "FE2REV1", "ReviewerPass1!").await;
    let (search_id, candidate_id) = create_search(&app, &token, "FE-CASE-2").await;

    review(&app, &token, "verify", &candidate_id, &search_id).await;

    let response = review(&app, &token, "verify", &candidate_id, &search_id).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let error = body_json(response).await;
    assert_eq!(error["code"], "SAME_REVIEWER_FORBIDDEN");
}

#[tokio::test]
async fn a_different_reviewer_finalizes_the_decision() {
    let state = state_with_second_review_required().await;
    let app = routes::router(state.clone());
    create_reviewer(&state, "FE3REV1").await;
    create_reviewer(&state, "FE3REV2").await;
    let token_a = login(&app, "FE3REV1", "ReviewerPass1!").await;
    let (search_id, candidate_id) = create_search(&app, &token_a, "FE-CASE-3").await;

    let response = review(&app, &token_a, "verify", &candidate_id, &search_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["status"], "needs_second_review");

    let token_b = login(&app, "FE3REV2", "ReviewerPass1!").await;
    let response = review(&app, &token_b, "verify", &candidate_id, &search_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["status"], "confirmed");
}

#[tokio::test]
async fn second_reviewer_has_final_say_even_on_disagreement() {
    let state = state_with_second_review_required().await;
    let app = routes::router(state.clone());
    create_reviewer(&state, "FE4REV1").await;
    create_reviewer(&state, "FE4REV2").await;
    let token_a = login(&app, "FE4REV1", "ReviewerPass1!").await;
    let (search_id, candidate_id) = create_search(&app, &token_a, "FE-CASE-4").await;

    // Reviewer A confirms first.
    review(&app, &token_a, "verify", &candidate_id, &search_id).await;

    // Reviewer B rejects — disagrees with A, and B's decision wins.
    let token_b = login(&app, "FE4REV2", "ReviewerPass1!").await;
    let response = review(&app, &token_b, "reject", &candidate_id, &search_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["status"], "rejected");
}

#[tokio::test]
async fn both_decisions_are_preserved_in_immutable_history() {
    let state = state_with_second_review_required().await;
    let app = routes::router(state.clone());
    create_reviewer(&state, "FE5REV1").await;
    create_reviewer(&state, "FE5REV2").await;
    let token_a = login(&app, "FE5REV1", "ReviewerPass1!").await;
    let (search_id, candidate_id) = create_search(&app, &token_a, "FE-CASE-5").await;

    review(&app, &token_a, "verify", &candidate_id, &search_id).await;
    let token_b = login(&app, "FE5REV2", "ReviewerPass1!").await;
    review(&app, &token_b, "verify", &candidate_id, &search_id).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/search/{search_id}/candidates/{candidate_id}/history"
                ))
                .header("authorization", format!("Bearer {token_a}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let history = body_json(response).await;
    let events = history.as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["decision"], "confirmed");
    assert_eq!(events[0]["reviewerName"], "Reviewer Tester");
    assert_eq!(events[1]["decision"], "confirmed");
}

#[tokio::test]
async fn require_second_review_disabled_finalizes_on_the_first_decision() {
    // Default AppState::for_tests() has require_second_review = false —
    // exactly today's pre-four-eyes behavior, unaffected by this feature.
    let state = AppState::for_tests().await;
    assert!(!state.require_second_review);
    let app = routes::router(state.clone());
    create_reviewer(&state, "FE6REV1").await;
    let token = login(&app, "FE6REV1", "ReviewerPass1!").await;
    let (search_id, candidate_id) = create_search(&app, &token, "FE-CASE-6").await;

    let response = review(&app, &token, "verify", &candidate_id, &search_id).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["status"], "confirmed");
}
