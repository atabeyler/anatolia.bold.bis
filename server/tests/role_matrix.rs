//! Table-driven role-matrix coverage: for every sensitive endpoint, every
//! one of the five RBAC roles is exercised and checked against
//! `permission.rs`'s policy — allowed roles must get past the role gate
//! (never a `403`), denied roles must always get exactly `403 FORBIDDEN`.
//! This is a systemic check on top of the endpoint-specific permission
//! tests elsewhere (e.g. `tests/audit.rs`, `tests/search.rs`), which each
//! only exercise one or two roles against their own endpoint.

use anatolia_bis_server::{db, db::AppState, roles, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use bcrypt::hash;
use serde_json::json;
use tower::ServiceExt;

const ALL_ROLES: [&str; 5] = [
    roles::SYSTEM_ADMIN,
    roles::SECURITY_ADMIN,
    roles::OPERATOR,
    roles::REVIEWER,
    roles::AUDITOR,
];

/// Creates an already-approved user with the given role directly through
/// `db::create_user` (bypassing the admin API, which can only mint
/// `OPERATOR`/`SYSTEM_ADMIN` accounts) and returns a logged-in access
/// token for it.
async fn login_as(app: &axum::Router, state: &AppState, role: &str) -> String {
    let user_code = format!("ROLE{}", &role[..role.len().min(6)]);
    let password = "RoleMatrix1!";
    let hashed = hash(password, bcrypt::DEFAULT_COST).unwrap();
    db::create_user(
        &state.backend,
        &user_code,
        Some(&format!("{}@example.test", user_code.to_lowercase())),
        "Role",
        "Tester",
        None,
        None,
        &hashed,
        role,
        true,
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
                    json!({ "userCode": user_code, "password": password }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "login must succeed for role {role}"
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    body["accessToken"].as_str().unwrap().to_string()
}

fn bearer(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn bearer_json(method: &str, uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// An empty (no fields) but well-formed `multipart/form-data` body — just
/// enough for axum's `Multipart` extractor to accept it and hand control
/// to the handler, so the role check inside `create_search_route` (which
/// runs before any field is read) is what actually gets exercised.
fn bearer_empty_multipart(uri: &str, token: &str) -> Request<Body> {
    let boundary = "----role-matrix-boundary";
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(format!("--{boundary}--\r\n")))
        .unwrap()
}

async fn status_for(app: &axum::Router, request: Request<Body>) -> StatusCode {
    app.clone().oneshot(request).await.unwrap().status()
}

/// Asserts that exactly the given `allowed` roles get past a policy gate:
/// every other role must see `403 FORBIDDEN`, and every allowed role must
/// see anything *other* than `403` (its own downstream validation status
/// is out of scope here — only the role gate is under test).
async fn assert_role_gate(
    app: &axum::Router,
    tokens: &std::collections::HashMap<&str, String>,
    allowed: &[&str],
    label: &str,
    build_request: impl Fn(&str) -> Request<Body>,
) {
    for role in ALL_ROLES {
        let token = &tokens[role];
        let status = status_for(app, build_request(token)).await;
        if allowed.contains(&role) {
            assert_ne!(
                status,
                StatusCode::FORBIDDEN,
                "{label}: role {role} should be allowed past the role gate, got 403"
            );
        } else {
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{label}: role {role} should be denied (403), got {status}"
            );
        }
    }
}

#[tokio::test]
async fn role_matrix_matches_permission_policy() {
    let state = AppState::for_tests().await;
    let app = routes::router(state.clone());

    let mut tokens = std::collections::HashMap::new();
    for role in ALL_ROLES {
        tokens.insert(role, login_as(&app, &state, role).await);
    }

    // GET /api/v1/audit — permission::can_view_audit_log.
    assert_role_gate(
        &app,
        &tokens,
        &[roles::AUDITOR, roles::SECURITY_ADMIN, roles::SYSTEM_ADMIN],
        "GET /api/v1/audit",
        |token| bearer("GET", "/api/v1/audit", token),
    )
    .await;

    // GET /api/v1/admin/users — permission::can_administer_users.
    assert_role_gate(
        &app,
        &tokens,
        &[roles::SYSTEM_ADMIN, roles::SECURITY_ADMIN],
        "GET /api/v1/admin/users",
        |token| bearer("GET", "/api/v1/admin/users", token),
    )
    .await;

    // GET /api/v1/search — permission::can_view_search (every role).
    assert_role_gate(&app, &tokens, &ALL_ROLES, "GET /api/v1/search", |token| {
        bearer("GET", "/api/v1/search", token)
    })
    .await;

    // GET /api/v1/search/{id}/status — permission::can_view_search (every
    // role). The search id doesn't need to exist: the role gate runs
    // before any database lookup.
    assert_role_gate(
        &app,
        &tokens,
        &ALL_ROLES,
        "GET /api/v1/search/{id}/status",
        |token| bearer("GET", "/api/v1/search/nonexistent/status", token),
    )
    .await;

    // POST /api/v1/search/face — permission::can_create_search.
    assert_role_gate(
        &app,
        &tokens,
        &[
            roles::OPERATOR,
            roles::REVIEWER,
            roles::SECURITY_ADMIN,
            roles::SYSTEM_ADMIN,
        ],
        "POST /api/v1/search/face",
        |token| bearer_empty_multipart("/api/v1/search/face", token),
    )
    .await;

    // POST /api/v1/candidates/{id}/verify — permission::can_review_candidate.
    // The candidate id doesn't need to exist: the role gate runs before
    // any database lookup.
    assert_role_gate(
        &app,
        &tokens,
        &[roles::REVIEWER, roles::SECURITY_ADMIN, roles::SYSTEM_ADMIN],
        "POST /api/v1/candidates/{id}/verify",
        |token| {
            bearer_json(
                "POST",
                "/api/v1/candidates/nonexistent/verify",
                token,
                json!({ "searchId": "nonexistent" }),
            )
        },
    )
    .await;

    // POST /api/v1/candidates — permission::can_manage_candidates.
    assert_role_gate(
        &app,
        &tokens,
        &[roles::OPERATOR, roles::SECURITY_ADMIN, roles::SYSTEM_ADMIN],
        "POST /api/v1/candidates",
        |token| {
            bearer_json(
                "POST",
                "/api/v1/candidates",
                token,
                json!({ "referenceCode": "RC-ROLE-MATRIX", "fullName": "Role Matrix" }),
            )
        },
    )
    .await;

    // POST /api/v1/candidates/{id}/evidence/collect — permission::can_manage_candidates.
    assert_role_gate(
        &app,
        &tokens,
        &[roles::OPERATOR, roles::SECURITY_ADMIN, roles::SYSTEM_ADMIN],
        "POST /api/v1/candidates/{id}/evidence/collect",
        |token| {
            bearer_json(
                "POST",
                "/api/v1/candidates/nonexistent/evidence/collect",
                token,
                json!({ "query": "Role Matrix" }),
            )
        },
    )
    .await;
}
