//! Tamper-resistance (hash chaining) tests for the audit trail.
//! `db::audit::insert_audit_event`
//! chains every row to the one before it; `GET /api/v1/audit/integrity`
//! recomputes the chain and reports whether it's intact.

use anatolia_bis_server::db::{self, AppState, DbBackend};
use anatolia_bis_server::routes;
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

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn seed_and_login_admin(app: &axum::Router, user_code: &str) -> String {
    std::env::set_var("ADMIN_SEED_TOKEN", "audit-integrity-seed-token");
    std::env::set_var("ADMIN_USER_CODE", user_code);
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "audit-integrity-admin@example.test");

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "audit-integrity-seed-token")
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
async fn chain_is_intact_after_several_events() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    // Seeding + a couple of logins generate several chained events.
    let admin_token = seed_and_login_admin(&app, "CHAINADM1").await;
    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "CHAINADM1", "password": "WrongPassword1!" }),
        ))
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit/integrity")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let report = body_json(response).await;
    assert_eq!(report["intact"], true);
    assert!(report["eventsChecked"].as_i64().unwrap() >= 2);
    assert!(report["breaks"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn integrity_endpoint_requires_a_privileged_role() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/integrity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tampering_with_a_stored_event_breaks_the_chain() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());

    let admin_token = seed_and_login_admin(&app, "CHAINADM2").await;

    // Directly rewrite a stored event's action, exactly what an attacker
    // with raw database access (but not the DB-role hardening this
    // checklist notes as still-missing — see item 16) would do.
    let DbBackend::Sqlite(pool) = &state.backend else {
        panic!("test harness always uses the sqlite backend");
    };
    sqlx::query("UPDATE audit_events SET action = 'TAMPERED' WHERE sequence = 1")
        .execute(pool)
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit/integrity")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let report = body_json(response).await;
    assert_eq!(report["intact"], false);
    let breaks = report["breaks"].as_array().unwrap();
    assert!(!breaks.is_empty());
    assert_eq!(breaks[0]["sequence"], 1);
}

#[tokio::test]
async fn verify_chain_reports_intact_on_a_fresh_database() {
    let state = AppState::for_tests().await;
    let report = db::verify_chain(&state.backend).await.unwrap();
    assert!(report.intact);
    assert_eq!(report.events_checked, 0);
}
