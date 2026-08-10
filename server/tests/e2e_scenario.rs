//! Full end-to-end scenario test (item 23 in the V1 closure checklist):
//! walks one continuous story through most of the subsystems this
//! project ties together — registration/approval, a real biometric
//! search, human review, OSINT evidence collection, the entity graph,
//! duplicate detection, session/device management, and audit-trail
//! integrity — in a single test, rather than each subsystem's own
//! isolated test file. This is deliberately not a substitute for those
//! per-feature tests (it doesn't re-cover their edge cases), but it does
//! catch a class of bug they individually can't: two features that each
//! pass in isolation but don't actually compose correctly end-to-end.

use anatolia_bis_server::{db::AppState, routes};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

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

fn valid_png_bytes(width: u32, height: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    let img = image::RgbImage::from_pixel(width, height, image::Rgb([120, 130, 140]));
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
            boundary: "----anatolia-e2e-boundary",
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

fn refresh_cookie(response: &axum::response::Response) -> String {
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    set_cookie.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn full_scenario_from_registration_to_audit_integrity() {
    let state = AppState::for_tests().await;
    let app = routes::router(state);

    // 1. An operator registers and awaits approval.
    std::env::set_var("ADMIN_SEED_TOKEN", "e2e-seed-token");
    std::env::set_var("ADMIN_USER_CODE", "E2EADMIN01");
    std::env::set_var("ADMIN_PASSWORD", "AdminPass1!");
    std::env::set_var("ADMIN_EMAIL", "e2e-admin@example.test");

    let register_response = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            "",
            json!({
                "firstName": "Eve",
                "lastName": "Operator",
                "nationalId": "11122233344",
                "email": "eve-operator@example.test",
                "password": "OperatorPass1!",
                "userCode": "E2EOPER01",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(register_response.status(), StatusCode::CREATED);

    // 2. Bootstrap the first SYSTEM_ADMIN and approve the operator.
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/seed-admin")
                .header("x-seed-token", "e2e-seed-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let admin_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "userCode": "E2EADMIN01", "password": "AdminPass1!" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let admin_token = body_json(admin_login).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

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
    let operator_id = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["userCode"] == "E2EOPER01")
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

    // 3. The operator signs in.
    let operator_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "userCode": "E2EOPER01", "password": "OperatorPass1!" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(operator_login.status(), StatusCode::OK);
    let operator_cookie = refresh_cookie(&operator_login);
    let operator_token = body_json(operator_login).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    // 4. Submit a real biometric search and wait for it to complete.
    let (content_type, body) = MultipartRequest::new()
        .text_field("caseReference", "E2E-CASE-001")
        .text_field("purpose", "Identity verification")
        .image_field("image", "probe.png", "image/png", &valid_png_bytes(64, 64))
        .finish();
    let search_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/search/face")
                .header("authorization", format!("Bearer {operator_token}"))
                .header("content-type", content_type)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(search_response.status(), StatusCode::ACCEPTED);
    let accepted = body_json(search_response).await;
    let search_id = accepted["search"]["id"].as_str().unwrap().to_string();

    let mut final_payload = None;
    for _ in 0..100 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/api/v1/search/{search_id}/status"))
                    .header("authorization", format!("Bearer {operator_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let payload = body_json(response).await;
        let status = payload["search"]["status"].as_str().unwrap_or("");
        if status != "queued" && status != "processing" {
            final_payload = Some(payload);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let final_payload = final_payload.expect("search did not complete in time");
    assert_eq!(final_payload["search"]["status"], "completed");
    let candidate_id = final_payload["candidates"][0]["candidateId"]
        .as_str()
        .unwrap()
        .to_string();

    // 5. A reviewer confirms the top candidate.
    std::env::set_var("ADMIN_USER_CODE", "E2EREV0001");
    let reviewer_register = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/auth/register",
            "",
            json!({
                "firstName": "Rita",
                "lastName": "Reviewer",
                "nationalId": "55566677788",
                "email": "rita-reviewer@example.test",
                "password": "ReviewerPass1!",
                "userCode": "E2EREV0001",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(reviewer_register.status(), StatusCode::CREATED);
    let reviewer_id = {
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
            .find(|u| u["userCode"] == "E2EREV0001")
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{reviewer_id}/approve"))
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/admin/users/{reviewer_id}/role"))
                .header("authorization", format!("Bearer {admin_token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "role": "REVIEWER" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let reviewer_login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "userCode": "E2EREV0001", "password": "ReviewerPass1!" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let reviewer_token = body_json(reviewer_login).await["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    let verify_response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/candidates/{candidate_id}/verify"),
            &reviewer_token,
            json!({ "searchId": search_id, "reason": "clear match, e2e scenario" }),
        ))
        .await
        .unwrap();
    assert_eq!(verify_response.status(), StatusCode::OK);

    // 6. Collect OSINT evidence for the confirmed candidate (mock
    // providers, since no real API keys are configured in tests).
    let collect_response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/candidates/{candidate_id}/evidence/collect"),
            &operator_token,
            json!({ "query": "Eve Operator" }),
        ))
        .await
        .unwrap();
    assert_eq!(collect_response.status(), StatusCode::OK);
    let collected = body_json(collect_response).await;
    assert!(
        !collected["items"].as_array().unwrap().is_empty(),
        "mock OSINT providers should return at least one evidence item"
    );

    let evidence_list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/candidates/{candidate_id}/evidence"))
                .header("authorization", format!("Bearer {operator_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(evidence_list.status(), StatusCode::OK);

    // 7. Record an entity-graph relation found during review.
    let relation_response = app
        .clone()
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/candidates/{candidate_id}/entity-graph"),
            &operator_token,
            json!({ "relationType": "alias", "value": "E. Operator" }),
        ))
        .await
        .unwrap();
    assert_eq!(relation_response.status(), StatusCode::OK);

    let relations_list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/candidates/{candidate_id}/entity-graph"))
                .header("authorization", format!("Bearer {operator_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let relations = body_json(relations_list).await;
    let relation_items = relations["items"].as_array().unwrap();
    // At least the manually-added alias, plus any `website` relations
    // auto-recorded from the evidence URLs collected in step 6.
    assert!(!relation_items.is_empty());
    assert!(relation_items
        .iter()
        .any(|r| r["relationType"] == "alias" && r["value"] == "E. Operator"));

    // 8. Possible-duplicates check runs without error (no assertion on
    // content — a single candidate has nothing to collide with).
    let duplicates_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/api/v1/candidates/{candidate_id}/possible-duplicates"
                ))
                .header("authorization", format!("Bearer {operator_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(duplicates_response.status(), StatusCode::OK);

    // 9. The operator checks their own session list, then signs out.
    let sessions_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/users/me/sessions")
                .header("authorization", format!("Bearer {operator_token}"))
                .header("cookie", &operator_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let sessions = body_json(sessions_response).await;
    let session_items = sessions["items"].as_array().unwrap();
    assert_eq!(session_items.len(), 1);
    assert_eq!(session_items[0]["isCurrent"], true);

    let logout_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("cookie", &operator_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_response.status(), StatusCode::OK);

    // 10. Every action above should be traceable, and the append-only
    // audit chain must still verify as intact.
    let integrity_response = app
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
    assert_eq!(integrity_response.status(), StatusCode::OK);
    let integrity = body_json(integrity_response).await;
    assert_eq!(integrity["intact"], true);
    assert!(integrity["eventsChecked"].as_i64().unwrap() > 0);
}
