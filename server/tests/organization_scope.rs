//! Object-level authorization tests for the organization/unit model
//! (madde 12-13): a member of one organization must never be able to see
//! another organization's searches or audit events, regardless of role —
//! except SYSTEM_ADMIN, the one explicit global exception. Legacy/
//! unassigned (orgless) data stays visible to everyone the role check
//! already allows, so introducing organizations doesn't retroactively
//! hide anything.

use anatolia_bis_server::{db, db::AppState, roles, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use bcrypt::hash;
use http_body_util::BodyExt;
use image::{DynamicImage, ImageFormat, RgbImage};
use serde_json::{json, Value};
use std::io::Cursor;
use tokio::sync::Mutex;
use tower::ServiceExt;

// ADMIN_SEED_TOKEN/ADMIN_USER_CODE/ADMIN_PASSWORD/ADMIN_EMAIL are
// process-wide env vars (see tests/auth.rs); serialize every test in this
// file so setting them for one seed-admin call can't race another test's
// concurrent write to the same vars.
static ENV_GUARD: Mutex<()> = Mutex::const_new(());

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

fn multipart(case_reference: &str) -> (String, Vec<u8>) {
    let boundary = "----org-scope-test-boundary";
    let mut body = Vec::new();
    for (name, value) in [
        ("caseReference", case_reference),
        ("purpose", "Identity verification"),
    ] {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(value.as_bytes());
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(
        b"Content-Disposition: form-data; name=\"image\"; filename=\"probe.png\"\r\nContent-Type: image/png\r\n\r\n",
    );
    body.extend_from_slice(&valid_png_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

async fn create_user_with_role(state: &AppState, user_code: &str, role: &str) -> String {
    db::create_user(
        &state.backend,
        user_code,
        Some(&format!("{}@example.test", user_code.to_lowercase())),
        "Org",
        "Tester",
        None,
        None,
        &hash("OrgPass1!", bcrypt::DEFAULT_COST).unwrap(),
        role,
        true,
    )
    .await
    .unwrap();
    user_code.to_string()
}

async fn login(app: &axum::Router, user_code: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "userCode": user_code, "password": "OrgPass1!" }).to_string(),
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

async fn user_id_by_code(app: &axum::Router, admin_token: &str, user_code: &str) -> String {
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
    users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["userCode"] == user_code)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn create_organization(app: &axum::Router, admin_token: &str, name: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/organizations")
                .header("authorization", format!("Bearer {admin_token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "name": name }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn assign_membership(app: &axum::Router, admin_token: &str, user_id: &str, org_id: &str) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/memberships")
                .header("authorization", format!("Bearer {admin_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "userId": user_id, "organizationId": org_id }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn create_search(app: &axum::Router, token: &str, case_reference: &str) -> String {
    let (content_type, body) = multipart(case_reference);
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
    body_json(response).await["search"]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// End-to-end setup shared by the tests below: a SYSTEM_ADMIN creates two
/// organizations, an OPERATOR in each, and each operator creates one
/// search — giving each search a distinct, real `organization_id`.
struct TwoOrgFixture {
    app: axum::Router,
    admin_token: String,
    org_a_token: String,
    org_b_token: String,
    search_a_id: String,
    search_b_id: String,
}

async fn set_up_two_orgs(seed_suffix: &str) -> TwoOrgFixture {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());

    std::env::set_var("ADMIN_SEED_TOKEN", format!("org-seed-{seed_suffix}"));
    std::env::set_var("ADMIN_USER_CODE", format!("ORGADMIN{seed_suffix}"));
    std::env::set_var("ADMIN_PASSWORD", "OrgPass1!");
    std::env::set_var(
        "ADMIN_EMAIL",
        format!("org-admin-{seed_suffix}@example.test"),
    );
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", format!("org-seed-{seed_suffix}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let admin_token = login(&app, &format!("ORGADMIN{seed_suffix}")).await;

    let org_a = create_organization(&app, &admin_token, &format!("Org A {seed_suffix}")).await;
    let org_b = create_organization(&app, &admin_token, &format!("Org B {seed_suffix}")).await;

    let user_a_code = format!("ORGAUSR{seed_suffix}");
    let user_b_code = format!("ORGBUSR{seed_suffix}");
    create_user_with_role(&state, &user_a_code, roles::OPERATOR).await;
    create_user_with_role(&state, &user_b_code, roles::OPERATOR).await;
    let user_a_id = user_id_by_code(&app, &admin_token, &user_a_code).await;
    let user_b_id = user_id_by_code(&app, &admin_token, &user_b_code).await;
    assign_membership(&app, &admin_token, &user_a_id, &org_a).await;
    assign_membership(&app, &admin_token, &user_b_id, &org_b).await;

    let org_a_token = login(&app, &user_a_code).await;
    let org_b_token = login(&app, &user_b_code).await;
    let search_a_id = create_search(&app, &org_a_token, &format!("ORG-A-CASE-{seed_suffix}")).await;
    let search_b_id = create_search(&app, &org_b_token, &format!("ORG-B-CASE-{seed_suffix}")).await;

    TwoOrgFixture {
        app,
        admin_token,
        org_a_token,
        org_b_token,
        search_a_id,
        search_b_id,
    }
}

#[tokio::test]
async fn a_member_of_org_a_cannot_view_org_bs_search() {
    let fx = set_up_two_orgs("1").await;

    let response = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/search/{}", fx.search_b_id))
                .header("authorization", format!("Bearer {}", fx.org_a_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_member_of_org_a_can_view_its_own_orgs_search() {
    let fx = set_up_two_orgs("2").await;

    let response = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/search/{}", fx.search_a_id))
                .header("authorization", format!("Bearer {}", fx.org_a_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn system_admin_bypasses_organization_scoping() {
    let fx = set_up_two_orgs("3").await;

    for search_id in [&fx.search_a_id, &fx.search_b_id] {
        let response = fx
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/search/{search_id}"))
                    .header("authorization", format!("Bearer {}", fx.admin_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn search_history_list_is_scoped_per_organization() {
    let fx = set_up_two_orgs("4").await;

    let response = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/search")
                .header("authorization", format!("Bearer {}", fx.org_a_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let payload = body_json(response).await;
    let ids: Vec<&str> = payload["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&fx.search_a_id.as_str()));
    assert!(!ids.contains(&fx.search_b_id.as_str()));
}

#[tokio::test]
async fn org_b_member_cannot_view_org_as_candidate_history_either() {
    let fx = set_up_two_orgs("5").await;

    // Fetch a real candidate id from search A's own results first.
    let response = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/search/{}/candidates", fx.search_a_id))
                .header("authorization", format!("Bearer {}", fx.org_a_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let candidates = body_json(response).await;
    let candidate_id = candidates[0]["candidateId"].as_str().unwrap().to_string();

    let response = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/search/{}/candidates/{}/history",
                    fx.search_a_id, candidate_id
                ))
                .header("authorization", format!("Bearer {}", fx.org_b_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // But the search's own org can.
    let response = fx
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/search/{}/candidates/{}/history",
                    fx.search_a_id, candidate_id
                ))
                .header("authorization", format!("Bearer {}", fx.org_a_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn only_system_admin_may_create_an_organization() {
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());
    create_user_with_role(&state, "ORGDENY1", roles::SECURITY_ADMIN).await;
    let token = login(&app, "ORGDENY1").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/organizations")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "name": "Should Fail" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "SECURITY_ADMIN must not be able to manage the organization structure"
    );
}

#[tokio::test]
async fn orgless_legacy_search_stays_visible_to_any_role_with_view_permission() {
    // No organizations/memberships configured at all — matches every
    // existing test in this codebase before this feature shipped.
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());
    create_user_with_role(&state, "ORGLESS1", roles::AUDITOR).await;
    let auditor_token = login(&app, "ORGLESS1").await;
    create_user_with_role(&state, "ORGLESS2", roles::OPERATOR).await;
    let operator_token = login(&app, "ORGLESS2").await;

    let search_id = create_search(&app, &operator_token, "ORGLESS-CASE").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/search/{search_id}"))
                .header("authorization", format!("Bearer {auditor_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
