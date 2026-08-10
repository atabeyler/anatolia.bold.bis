//! Entity graph endpoints (item 10 in `docs/HARDENING_CHECKLIST.md`):
//! manual relations, automatic website relations from evidence
//! collection, and organization scoping — the same object-level
//! authorization rule already proven for searches in
//! `organization_scope.rs`, applied here to candidates/entity relations.

use anatolia_bis_server::{db, db::AppState, roles, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use bcrypt::hash;
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

async fn create_user_with_role(state: &AppState, user_code: &str, role: &str) -> String {
    db::create_user(
        &state.backend,
        user_code,
        Some(&format!("{}@example.test", user_code.to_lowercase())),
        "Graph",
        "Tester",
        None,
        None,
        &hash("GraphPass1!", bcrypt::DEFAULT_COST).unwrap(),
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
                    json!({ "userCode": user_code, "password": "GraphPass1!" }).to_string(),
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
    body_json(response).await["items"]
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
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/organizations",
            admin_token,
            json!({ "name": name }),
        ))
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
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/memberships",
            admin_token,
            json!({ "userId": user_id, "organizationId": org_id }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

async fn create_candidate(app: &axum::Router, token: &str, reference_code: &str) -> String {
    let response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/candidates",
            token,
            json!({ "referenceCode": reference_code, "fullName": "Entity Graph Test" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body_json(response).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

struct TwoOrgFixture {
    app: axum::Router,
    admin_token: String,
    org_a_token: String,
    org_b_token: String,
    candidate_a_id: String,
}

async fn set_up_two_orgs(seed_suffix: &str) -> TwoOrgFixture {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());

    std::env::set_var("ADMIN_SEED_TOKEN", format!("entgraph-seed-{seed_suffix}"));
    std::env::set_var("ADMIN_USER_CODE", format!("EGADMIN{seed_suffix}"));
    std::env::set_var("ADMIN_PASSWORD", "GraphPass1!");
    std::env::set_var(
        "ADMIN_EMAIL",
        format!("entgraph-admin-{seed_suffix}@example.test"),
    );
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", format!("entgraph-seed-{seed_suffix}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let admin_token = login(&app, &format!("EGADMIN{seed_suffix}")).await;

    let org_a = create_organization(&app, &admin_token, &format!("EG Org A {seed_suffix}")).await;
    let org_b = create_organization(&app, &admin_token, &format!("EG Org B {seed_suffix}")).await;

    let user_a_code = format!("EGAUSR{seed_suffix}");
    let user_b_code = format!("EGBUSR{seed_suffix}");
    create_user_with_role(&state, &user_a_code, roles::OPERATOR).await;
    create_user_with_role(&state, &user_b_code, roles::OPERATOR).await;
    let user_a_id = user_id_by_code(&app, &admin_token, &user_a_code).await;
    let user_b_id = user_id_by_code(&app, &admin_token, &user_b_code).await;
    assign_membership(&app, &admin_token, &user_a_id, &org_a).await;
    assign_membership(&app, &admin_token, &user_b_id, &org_b).await;

    let org_a_token = login(&app, &user_a_code).await;
    let org_b_token = login(&app, &user_b_code).await;
    let candidate_a_id =
        create_candidate(&app, &org_a_token, &format!("EG-CAND-A-{seed_suffix}")).await;

    TwoOrgFixture {
        app,
        admin_token,
        org_a_token,
        org_b_token,
        candidate_a_id,
    }
}

#[tokio::test]
async fn owner_org_member_can_add_and_read_a_manual_relation() {
    let fixture = set_up_two_orgs("1").await;

    let response = fixture
        .app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/candidates/{}/entity-graph", fixture.candidate_a_id),
            &fixture.org_a_token,
            json!({ "relationType": "alias", "value": "Jon Doe" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let added = body_json(response).await;
    assert_eq!(added["relationType"], "alias");
    assert_eq!(added["value"], "Jon Doe");

    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/candidates/{}/entity-graph",
                    fixture.candidate_a_id
                ))
                .header("authorization", format!("Bearer {}", fixture.org_a_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["relationType"], "alias");
    assert_eq!(items[0]["value"], "Jon Doe");
}

#[tokio::test]
async fn a_different_orgs_member_cannot_read_or_add_relations() {
    let fixture = set_up_two_orgs("2").await;

    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/candidates/{}/entity-graph",
                    fixture.candidate_a_id
                ))
                .header("authorization", format!("Bearer {}", fixture.org_b_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = fixture
        .app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/candidates/{}/entity-graph", fixture.candidate_a_id),
            &fixture.org_b_token,
            json!({ "relationType": "alias", "value": "Should not be added" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn system_admin_bypasses_organization_scoping_for_the_entity_graph() {
    let fixture = set_up_two_orgs("3").await;

    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/candidates/{}/entity-graph",
                    fixture.candidate_a_id
                ))
                .header("authorization", format!("Bearer {}", fixture.admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_unknown_relation_type_is_rejected() {
    let fixture = set_up_two_orgs("4").await;

    let response = fixture
        .app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/candidates/{}/entity-graph", fixture.candidate_a_id),
            &fixture.org_a_token,
            json!({ "relationType": "phone_number", "value": "+90 555 000 0000" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn collecting_evidence_with_a_url_automatically_records_a_website_relation() {
    let fixture = set_up_two_orgs("5").await;

    let response = fixture
        .app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!(
                "/api/v1/candidates/{}/evidence/collect",
                fixture.candidate_a_id
            ),
            &fixture.org_a_token,
            json!({ "query": "Entity Graph Test" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/candidates/{}/entity-graph",
                    fixture.candidate_a_id
                ))
                .header("authorization", format!("Bearer {}", fixture.org_a_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    let items = body["items"].as_array().unwrap();
    // The mock web-search and mock-news providers each return one item
    // with a URL; the mock-social provider's item has no URL — see
    // src/osint/mock.rs.
    let website_items: Vec<&Value> = items
        .iter()
        .filter(|i| i["relationType"] == "website")
        .collect();
    assert_eq!(
        website_items.len(),
        2,
        "expected one website relation per URL-bearing evidence item"
    );
    for item in &website_items {
        assert!(
            item["evidenceId"].is_string(),
            "website relation must carry evidence provenance"
        );
    }
}

/// Item 21 in `docs/HARDENING_CHECKLIST.md`: organization scoping was
/// only enforced on the entity-graph routes when they were added; every
/// other candidate-scoped endpoint (templates, evidence, possible-
/// duplicates, reference-photo upload) read/wrote candidate data with no
/// such check at all — a real IDOR. These tests cover the fix.
#[tokio::test]
async fn a_different_orgs_member_cannot_list_templates_or_evidence_or_possible_duplicates() {
    let fixture = set_up_two_orgs("6").await;

    for uri in [
        format!("/api/v1/candidates/{}/templates", fixture.candidate_a_id),
        format!("/api/v1/candidates/{}/evidence", fixture.candidate_a_id),
        format!(
            "/api/v1/candidates/{}/possible-duplicates",
            fixture.candidate_a_id
        ),
    ] {
        let response = fixture
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&uri)
                    .header("authorization", format!("Bearer {}", fixture.org_b_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "expected 403 for org B reading org A's candidate via {uri}"
        );
    }

    // Same-org access still works — the fix must not have overcorrected
    // into blocking everyone.
    let response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/candidates/{}/templates",
                    fixture.candidate_a_id
                ))
                .header("authorization", format!("Bearer {}", fixture.org_a_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_different_orgs_member_cannot_collect_evidence_for_another_orgs_candidate() {
    let fixture = set_up_two_orgs("7").await;

    let response = fixture
        .app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!(
                "/api/v1/candidates/{}/evidence/collect",
                fixture.candidate_a_id
            ),
            &fixture.org_b_token,
            json!({ "query": "Should not be allowed" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
