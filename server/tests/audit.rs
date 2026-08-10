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

/// Bootstraps a fresh admin account, logs in, and returns its access
/// token — a login by itself already generates at least one
/// AUTH_LOGIN_SUCCESS audit event, which the tests below rely on.
async fn seed_and_login_admin(app: &axum::Router, user_code: &str) -> String {
    std::env::set_var("ADMIN_SEED_TOKEN", "audit-test-seed-token");
    std::env::set_var("ADMIN_USER_CODE", user_code);
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "audit-admin@example.test");

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "audit-test-seed-token")
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
async fn audit_endpoint_requires_a_privileged_role() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    // No token at all.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // An OPERATOR (self-registered, admin-approved) is not privileged
    // enough to read the audit trail.
    let admin_token = seed_and_login_admin(&app, "AUDITADM1").await;

    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            json!({
                "firstName": "Op",
                "lastName": "Erator",
                "nationalId": "55566677788",
                "email": "operator@example.test",
                "password": "OperatorPass1!",
                "userCode": "AUDITOP1",
            }),
        ))
        .await
        .unwrap();

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
    let operator_id = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["userCode"] == "AUDITOP1")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{operator_id}/approve"))
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
            json!({ "userCode": "AUDITOP1", "password": "OperatorPass1!" }),
        ))
        .await
        .unwrap();
    let operator_token = body_json(response).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit")
                .header("authorization", format!("Bearer {operator_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // SYSTEM_ADMIN (the seeded admin) can read it.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_and_registration_generate_audit_events_visible_through_the_endpoint() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    let admin_token = seed_and_login_admin(&app, "AUDITADM2").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit?action=AUTH_LOGIN_SUCCESS")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    let items = payload["items"].as_array().unwrap();
    assert!(
        !items.is_empty(),
        "expected at least the admin's own login to be recorded"
    );
    assert!(items
        .iter()
        .all(|item| item["action"] == "AUTH_LOGIN_SUCCESS"));
    assert!(items[0]["actorUserCode"] == "AUDITADM2");
    assert!(payload["total"].as_i64().unwrap() >= 1);

    // A failed login (wrong password) is also recorded, with the right
    // action/result — not silently dropped.
    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": "AUDITADM2", "password": "WrongPassword1!" }),
        ))
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit?action=AUTH_LOGIN_FAILED")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let payload = body_json(response).await;
    assert!(!payload["items"].as_array().unwrap().is_empty());
}

fn authed_json_request(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn create_organization(app: &axum::Router, admin_token: &str, name: &str) -> String {
    app.clone()
        .oneshot(authed_json_request(
            "POST",
            "/api/v1/admin/organizations",
            admin_token,
            json!({ "name": name }),
        ))
        .await
        .unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/admin/organizations")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    body_json(response)
        .await
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["name"] == name)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Registers and admin-approves a user, deliberately stopping short of
/// logging in — a caller that needs to assign an organization membership
/// before the account's first-ever login (so that login's own audit
/// event is correctly org-scoped, rather than recorded as an "orgless"
/// event visible to every role, per `can_view_scoped_resource`'s
/// documented orgless-stays-visible behavior) needs that ordering.
async fn register_and_approve(
    app: &axum::Router,
    admin_token: &str,
    user_code: &str,
    national_id: &str,
) -> String {
    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            json!({
                "firstName": "Audit",
                "lastName": "Scoped",
                "nationalId": national_id,
                "email": format!("{}@example.test", user_code.to_lowercase()),
                "password": "ScopedPass1!",
                "userCode": user_code,
            }),
        ))
        .await
        .unwrap();

    let users_response = app
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
    let users = body_json(users_response).await;
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

    user_id
}

async fn login(app: &axum::Router, user_code: &str, password: &str) -> String {
    let login_response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/login",
            json!({ "userCode": user_code, "password": password }),
        ))
        .await
        .unwrap();
    body_json(login_response).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn assign_membership(app: &axum::Router, admin_token: &str, user_id: &str, org_id: &str) {
    app.clone()
        .oneshot(authed_json_request(
            "POST",
            "/api/v1/admin/memberships",
            admin_token,
            json!({ "userId": user_id, "organizationId": org_id }),
        ))
        .await
        .unwrap();
}

/// An `AUDITOR` in one organization must never see another organization's
/// audit events, even though the `AUDITOR` role globally permits reading
/// the audit trail — the same object-level authorization
/// (`can_view_scoped_resource`) already proven for searches and
/// candidate-scoped routes must also cover this endpoint. See "Not yet
/// covered" corrections in `docs/SECURITY_ARCHITECTURE.md`.
#[tokio::test]
async fn an_auditor_in_one_organization_cannot_see_another_organizations_events() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let admin_token = seed_and_login_admin(&app, "AUDITSCOP").await;

    let org_a = create_organization(&app, &admin_token, "Audit Scope Org A").await;
    let org_b = create_organization(&app, &admin_token, "Audit Scope Org B").await;

    // Both accounts are registered, approved, and given their org
    // membership *before* their first login, so that first login's own
    // audit event is correctly org-scoped rather than recorded as an
    // orgless event visible to every role.
    let auditor_id = register_and_approve(&app, &admin_token, "AUDSCOPEA", "10101010101").await;
    app.clone()
        .oneshot(authed_json_request(
            "POST",
            &format!("/api/v1/admin/users/{auditor_id}/role"),
            &admin_token,
            json!({ "role": "AUDITOR" }),
        ))
        .await
        .unwrap();
    assign_membership(&app, &admin_token, &auditor_id, &org_a).await;
    let auditor_token = login(&app, "AUDSCOPEA", "ScopedPass1!").await;

    let org_b_user_id = register_and_approve(&app, &admin_token, "AUDSCOPEB", "20202020202").await;
    assign_membership(&app, &admin_token, &org_b_user_id, &org_b).await;
    // This is org B's member's first login — its audit event is stamped
    // with org B's id, since the membership above was assigned first.
    login(&app, "AUDSCOPEB", "ScopedPass1!").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit?action=AUTH_LOGIN_SUCCESS&pageSize=200")
                .header("authorization", format!("Bearer {auditor_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    let items = payload["items"].as_array().unwrap();
    assert!(
        items
            .iter()
            .all(|item| item["actorUserCode"] != "AUDSCOPEB"),
        "an org A auditor must not see org B's login events: {items:?}"
    );
}

#[tokio::test]
async fn audit_page_size_is_clamped_to_the_max() {
    let _guard = ENV_GUARD.lock().await;
    let state = AppState::for_tests().await;
    let app = routes::router(state);
    let admin_token = seed_and_login_admin(&app, "AUDITADM3").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/audit?pageSize=99999")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let payload = body_json(response).await;
    assert_eq!(payload["pageSize"].as_i64().unwrap(), 200);
}
