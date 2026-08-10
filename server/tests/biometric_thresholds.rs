//! `GET /api/v1/admin/biometric-thresholds` (item 3 in the V1-closure
//! checklist): admin-only visibility into calibrated FAR/FRR thresholds
//! recorded by `server/src/bin/calibrate.rs --save-threshold`.

use anatolia_bis_server::{db, db::AppState, routes};
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

#[tokio::test]
async fn admin_can_list_calibrated_thresholds_and_others_cannot() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;

    db::save_calibrated_threshold(&state.backend, "sface", "2021dec", 0.88, 0.0, 6)
        .await
        .expect("save_calibrated_threshold failed");

    let app = routes::router(state.clone());

    std::env::set_var("ADMIN_SEED_TOKEN", "threshold-test-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "THRESHADM1");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "threshold-admin@example.test");
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "threshold-test-seed-token")
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
                    json!({ "userCode": "THRESHADM1", "password": "AdminPass1!" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let admin_token = body_json(response).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/biometric-thresholds")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    let items = payload["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["modelName"], "sface");
    assert_eq!(items[0]["modelVersion"], "2021dec");
    assert_eq!(items[0]["threshold"], 0.88);

    // No auth at all — must not leak the list.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/biometric-thresholds")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // require_admin (server/src/admin.rs) reports every denial —
    // missing/invalid token alike — as FORBIDDEN, same as every other
    // admin-only endpoint in this codebase.
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn saving_a_threshold_twice_for_the_same_model_replaces_it() {
    let state = AppState::for_tests().await;

    db::save_calibrated_threshold(&state.backend, "sface", "2021dec", 0.80, 0.05, 10)
        .await
        .unwrap();
    db::save_calibrated_threshold(&state.backend, "sface", "2021dec", 0.85, 0.02, 20)
        .await
        .unwrap();

    let thresholds = db::list_calibrated_thresholds(&state.backend)
        .await
        .unwrap();
    assert_eq!(thresholds.len(), 1);
    assert_eq!(thresholds[0].threshold, 0.85);
    assert_eq!(thresholds[0].pair_count, 20);
}
