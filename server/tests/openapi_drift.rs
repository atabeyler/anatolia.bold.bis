//! Docs-drift guard for `docs/openapi.json` (item 40 in
//! `docs/HARDENING_CHECKLIST.md`): every path/method listed there must
//! correspond to a route the router actually serves. This won't catch a
//! route added to `routes::router` and never documented (axum 0.7 doesn't
//! expose a way to enumerate a built `Router`'s paths), but it does catch
//! the more common failure mode — a route renamed or removed in code
//! while the spec still describes the old one — since an unmatched axum
//! route always answers with an empty `404` body, while every real
//! handler in this codebase always writes some body (a JSON `ApiError`,
//! a JSON payload, or an HTML page).

use anatolia_bis_server::{db::AppState, routes};
use axum::body::Body;
use axum::http::Request;
use serde_json::Value;
use tower::ServiceExt;

fn load_openapi_paths() -> Vec<(String, String)> {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/openapi.json"))
        .expect("docs/openapi.json must exist");
    let doc: Value = serde_json::from_str(&raw).expect("docs/openapi.json must be valid JSON");
    let mut routes = Vec::new();
    for (path, methods) in doc["paths"].as_object().expect("paths must be an object") {
        for (method, _) in methods.as_object().expect("path entry must be an object") {
            routes.push((method.to_uppercase(), path.clone()));
        }
    }
    routes
}

/// Replaces every `{param}` segment with a fixed placeholder — the drift
/// check only cares whether the route exists, not whether a real resource
/// does, so any syntactically valid value works.
fn concrete_uri(template: &str) -> String {
    template
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "openapi-drift-placeholder"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[tokio::test]
async fn every_documented_path_is_a_real_route() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    for (method, template) in load_openapi_paths() {
        let uri = concrete_uri(&template);
        let mut builder = Request::builder().method(method.as_str()).uri(&uri);
        let body = if method == "POST" || method == "PATCH" {
            if uri.contains("/search/face") {
                builder = builder.header(
                    "content-type",
                    "multipart/form-data; boundary=----openapi-drift-boundary",
                );
                Body::from("------openapi-drift-boundary--\r\n")
            } else {
                builder = builder.header("content-type", "application/json");
                Body::from("{}")
            }
        } else {
            Body::empty()
        };
        let request = builder.body(body).unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            !(status == axum::http::StatusCode::NOT_FOUND && bytes.is_empty()),
            "documented route {method} {template} does not appear to exist in the router \
             (got 404 with an empty body, axum's signature for an unmatched route)"
        );
    }
}
