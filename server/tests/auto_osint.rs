//! `AUTO_OSINT_AFTER_BIOMETRIC_SEARCH`: a completed biometric search
//! automatically runs web/news OSINT evidence collection against its
//! top-scoring candidates — see `search::run_auto_osint`.

use anatolia_bis_server::db::AppState;
use anatolia_bis_server::osint::mock::{MockNewsProvider, MockSocialProvider};
use anatolia_bis_server::osint::{
    EvidenceItem, EvidenceOrchestrator, OsintError, WebSearchProvider,
};
use anatolia_bis_server::routes;
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

static ENV_GUARD: Mutex<()> = Mutex::const_new(());

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn valid_png_bytes(width: u32, height: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    let img = image::RgbImage::from_pixel(width, height, image::Rgb([90, 100, 110]));
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
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
            boundary: "----anatolia-auto-osint-test-boundary",
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

async fn seed_admin_and_login(app: &axum::Router, user_code: &str, seed_token: &str) -> String {
    std::env::set_var("ADMIN_SEED_TOKEN", seed_token);
    std::env::set_var("ADMIN_USER_CODE", user_code);
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "auto-osint-admin@example.test");

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
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "userCode": user_code, "password": "AdminPass1!" })
                        .to_string(),
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

/// Submits a search and polls `GET /api/v1/search/{id}/status` until the
/// biometric phase leaves `queued`/`processing`. Unlike the equivalent
/// helper in `tests/search.rs`, this keeps polling a little further,
/// bounded, until `externalEvidenceStatus` is populated too (or the bound
/// is hit) — `run_auto_osint` runs after the search is already marked
/// `completed`, so a poller can otherwise observe `completed` with
/// `externalEvidenceStatus: null` in the small window before it finishes.
async fn submit_search_and_wait_for_osint(
    app: &axum::Router,
    token: &str,
    case_reference: &str,
) -> Value {
    let (content_type, body) = MultipartRequest::new()
        .text_field("caseReference", case_reference)
        .text_field("purpose", "Auto-OSINT integration test")
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

    let mut last = Value::Null;
    for _ in 0..200 {
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
        let payload = body_json(response).await;
        let status = payload["search"]["status"]
            .as_str()
            .unwrap_or("")
            .to_string();
        last = payload;
        if status != "queued" && status != "processing" {
            if last["search"]["externalEvidenceStatus"].is_null() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
            return last;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    last
}

async fn list_evidence(app: &axum::Router, token: &str, candidate_id: &str) -> Vec<Value> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/candidates/{candidate_id}/evidence"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(response).await["items"]
        .as_array()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn disabled_by_default_never_triggers_evidence_collection() {
    let _guard = ENV_GUARD.lock().await;
    // AppState::for_tests() defaults auto_osint_after_biometric_search to
    // false — this is the "do nothing extra" baseline every other test in
    // this file deviates from explicitly.
    let state = AppState::for_tests().await;
    assert!(!state.auto_osint_after_biometric_search);
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "AUTOOSINT1", "auto-osint-test-seed-1").await;

    let result = submit_search_and_wait_for_osint(&app, &token, "AUTO-OSINT-CASE-1").await;
    assert_eq!(result["search"]["status"], "completed");
    assert!(result["search"]["externalEvidenceStatus"].is_null());

    let candidates = result["candidates"].as_array().unwrap();
    assert!(!candidates.is_empty());
    for candidate in candidates {
        let candidate_id = candidate["candidateId"].as_str().unwrap();
        let evidence = list_evidence(&app, &token, candidate_id).await;
        assert!(
            evidence.is_empty(),
            "no evidence should be collected when AUTO_OSINT_AFTER_BIOMETRIC_SEARCH is off"
        );
    }
}

#[tokio::test]
async fn enabled_automatically_collects_web_and_news_evidence_but_never_social() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState {
        auto_osint_after_biometric_search: true,
        osint_auto_max_candidates: 2,
        ..AppState::for_tests().await
    };
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "AUTOOSINT2", "auto-osint-test-seed-2").await;

    let result = submit_search_and_wait_for_osint(&app, &token, "AUTO-OSINT-CASE-2").await;
    assert_eq!(result["search"]["status"], "completed");

    let external_status = &result["search"]["externalEvidenceStatus"];
    assert!(
        !external_status.is_null(),
        "externalEvidenceStatus should be populated once auto-OSINT finishes"
    );
    // AppState::for_tests() wires EvidenceOrchestrator::mock() — every
    // slot is its mock fallback, so both attempted slots must honestly
    // report "mock", never "completed" (which would claim a real result).
    assert_eq!(external_status["web"], "mock");
    assert_eq!(external_status["news"], "mock");
    // The automatic trigger never touches the social slot at all — see
    // `EvidenceOrchestrator::collect_web_and_news`.
    assert_eq!(external_status["social"], "not_configured");
    assert_eq!(external_status["reverseImage"], "not_configured");

    let candidates = result["candidates"].as_array().unwrap();
    assert!(
        candidates.len() >= 2,
        "the seeded mock candidates give at least two ranked results"
    );

    // Only the top osint_auto_max_candidates (2) get evidence collected.
    let mut candidates_with_evidence = 0;
    for candidate in candidates {
        let candidate_id = candidate["candidateId"].as_str().unwrap();
        let evidence = list_evidence(&app, &token, candidate_id).await;
        if !evidence.is_empty() {
            candidates_with_evidence += 1;
            for item in &evidence {
                let provider = item["providerName"].as_str().unwrap();
                assert_ne!(
                    provider, "mock-social",
                    "the automatic trigger must never store social-provider evidence"
                );
                assert!(provider == "mock-web-search" || provider == "mock-news");
            }
        }
    }
    assert_eq!(
        candidates_with_evidence, 2,
        "exactly osint_auto_max_candidates candidates should have received automatic evidence"
    );
}

#[tokio::test]
async fn a_re_run_search_does_not_duplicate_previously_stored_evidence() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState {
        auto_osint_after_biometric_search: true,
        osint_auto_max_candidates: 1,
        ..AppState::for_tests().await
    };
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "AUTOOSINT3", "auto-osint-test-seed-3").await;

    let first = submit_search_and_wait_for_osint(&app, &token, "AUTO-OSINT-CASE-3A").await;
    let top_candidate_id = first["candidates"].as_array().unwrap()[0]["candidateId"]
        .as_str()
        .unwrap()
        .to_string();
    let after_first = list_evidence(&app, &token, &top_candidate_id).await;
    assert!(!after_first.is_empty());

    // The mock providers are deterministic for a given query (the
    // candidate's name never changes between runs), and the top-scoring
    // candidate for this deterministic probe image is the same each time
    // — a second search should collect against the same candidate again
    // without duplicating the evidence rows already stored for it.
    let second = submit_search_and_wait_for_osint(&app, &token, "AUTO-OSINT-CASE-3B").await;
    let second_top_candidate_id = second["candidates"].as_array().unwrap()[0]["candidateId"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        top_candidate_id, second_top_candidate_id,
        "same deterministic probe image against the same seeded candidates ranks the same candidate first"
    );

    let after_second = list_evidence(&app, &token, &top_candidate_id).await;
    assert_eq!(
        after_first.len(),
        after_second.len(),
        "re-running auto-OSINT against the same candidate must not duplicate evidence rows"
    );
}

/// A web-search provider that always fails, to exercise the "one provider
/// down, the other still contributes" path end to end through the
/// automatic trigger — mirrors `osint::tests::FailingProvider` but lives
/// here since that one is private to `osint::mod`'s own unit tests.
struct FailingWebSearchProvider;

#[async_trait]
impl WebSearchProvider for FailingWebSearchProvider {
    fn name(&self) -> &'static str {
        "failing-web-search"
    }
    async fn search(&self, _query: &str) -> Result<Vec<EvidenceItem>, OsintError> {
        Err(OsintError::ProviderUnavailable(
            "simulated outage".to_string(),
        ))
    }
}

#[tokio::test]
async fn one_failing_provider_reports_partial_without_failing_the_search() {
    let _guard = ENV_GUARD.lock().await;
    let orchestrator = EvidenceOrchestrator::new(
        vec![Arc::new(FailingWebSearchProvider)],
        vec![Arc::new(MockNewsProvider)],
        vec![Arc::new(MockSocialProvider)],
    );
    let state = AppState {
        auto_osint_after_biometric_search: true,
        osint_auto_max_candidates: 1,
        osint_orchestrator: Arc::new(orchestrator),
        ..AppState::for_tests().await
    };
    let app = routes::router(state);
    let token = seed_admin_and_login(&app, "AUTOOSINT4", "auto-osint-test-seed-4").await;

    let result = submit_search_and_wait_for_osint(&app, &token, "AUTO-OSINT-CASE-4").await;
    assert_eq!(
        result["search"]["status"], "completed",
        "a failing OSINT provider must never fail the biometric search itself"
    );
    let external_status = &result["search"]["externalEvidenceStatus"];
    assert_eq!(external_status["web"], "failed");
    // News still uses the real (well, mock-but-not-failing) provider and
    // must still report its own honest status independent of web's
    // failure.
    assert_eq!(external_status["news"], "mock");

    let top_candidate_id = result["candidates"].as_array().unwrap()[0]["candidateId"]
        .as_str()
        .unwrap();
    let evidence = list_evidence(&app, &token, top_candidate_id).await;
    assert!(
        evidence
            .iter()
            .all(|item| item["providerName"] != "failing-web-search"),
        "the failing provider must never have stored evidence"
    );
    assert!(
        evidence
            .iter()
            .any(|item| item["providerName"] == "mock-news"),
        "news evidence should still be collected despite web search failing"
    );
}
