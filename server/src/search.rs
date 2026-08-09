use axum::extract::{Multipart, Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::{action, result as audit_result, AuditRecorder};
use crate::auth::{auth_user_from_headers, require_role};
use crate::biometric::{BiometricProvider, MockBiometricProvider};
use crate::db::{
    create_search, list_candidates, list_search_candidates, list_searches, load_candidate_by_id,
    load_search_by_id, load_user_by_id, set_search_candidate_status, AppState, CandidateRow,
    SearchCandidateRow, SearchRow,
};
use crate::error::ApiError;
use crate::roles;

const SEARCH_ROLES: &[&str] = &[
    roles::OPERATOR,
    roles::REVIEWER,
    roles::SECURITY_ADMIN,
    roles::SYSTEM_ADMIN,
];
const REVIEW_ROLES: &[&str] = &[roles::REVIEWER, roles::SECURITY_ADMIN, roles::SYSTEM_ADMIN];
// Everyone who may see search/candidate records: the search/review roles
// above, plus AUDITOR — whose entire purpose is read-only oversight of
// exactly this data, per docs/SECURITY_ARCHITECTURE.md.
const VIEW_ROLES: &[&str] = &[
    roles::OPERATOR,
    roles::REVIEWER,
    roles::SECURITY_ADMIN,
    roles::SYSTEM_ADMIN,
    roles::AUDITOR,
];
const TOP_K: usize = 5;

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

fn search_json(search: &SearchRow) -> serde_json::Value {
    json!({
        "id": search.id,
        "caseReference": search.case_reference,
        "purpose": search.purpose,
        "requestedByName": search.requested_by_name,
        "status": search.status,
        "latitude": search.latitude,
        "longitude": search.longitude,
        "createdAt": search.created_at,
    })
}

fn search_candidate_json(row: &SearchCandidateRow) -> serde_json::Value {
    json!({
        "id": row.id,
        "candidateId": row.candidate_id,
        "referenceCode": row.candidate_reference_code,
        "fullName": row.candidate_full_name,
        "score": row.score,
        "status": row.status,
        "reviewedByName": row.reviewed_by_name,
        "reviewedAt": row.reviewed_at,
    })
}

fn candidate_json(candidate: &CandidateRow) -> serde_json::Value {
    json!({
        "id": candidate.id,
        "referenceCode": candidate.reference_code,
        "fullName": candidate.full_name,
        "notes": candidate.notes,
    })
}

/// `POST /api/v1/search/face` — multipart form: `caseReference`, `purpose`,
/// `image`. Runs the (currently mock) `BiometricProvider` over every known
/// candidate and stores the ranked, scored result — never a verdict, see
/// CLAUDE.md's "candidates, not verdicts" principle.
pub async fn create_search_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !SEARCH_ROLES.contains(&claims.role.as_str()) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }

    let mut case_reference: Option<String> = None;
    let mut purpose: Option<String> = None;
    let mut image_bytes: Option<Vec<u8>> = None;
    let mut latitude: Option<f64> = None;
    let mut longitude: Option<f64> = None;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => {
                return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response()
            }
        };
        match field.name().unwrap_or("") {
            "caseReference" => case_reference = field.text().await.ok(),
            "purpose" => purpose = field.text().await.ok(),
            "image" => image_bytes = field.bytes().await.ok().map(|b| b.to_vec()),
            "latitude" => latitude = field.text().await.ok().and_then(|v| v.parse().ok()),
            "longitude" => longitude = field.text().await.ok().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }

    let case_reference = case_reference.unwrap_or_default().trim().to_string();
    let purpose = purpose.unwrap_or_default().trim().to_string();
    let Some(image_bytes) = image_bytes.filter(|b| !b.is_empty()) else {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    };
    if case_reference.is_empty() || purpose.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let requester_name = match load_user_by_id(&state.backend, &claims.id).await {
        Ok(Some(user)) => format!("{} {}", user.first_name, user.last_name)
            .trim()
            .to_string(),
        _ => claims.user_code.clone(),
    };

    let search = match create_search(
        &state.backend,
        &case_reference,
        &purpose,
        &claims.id,
        &requester_name,
        latitude,
        longitude,
    )
    .await
    {
        Ok(Some(search)) => search,
        _ => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };

    AuditRecorder::new(action::SEARCH_CREATED, audit_result::SUCCESS, rid.clone())
        .actor(&claims)
        .headers(&headers)
        .case_reference(&case_reference)
        .resource("search", &search.id)
        .save(&state)
        .await;

    let candidates = match list_candidates(&state.backend).await {
        Ok(rows) => rows,
        Err(_) => {
            AuditRecorder::new(action::SEARCH_FAILED, audit_result::FAILURE, rid.clone())
                .actor(&claims)
                .headers(&headers)
                .case_reference(&case_reference)
                .resource("search", &search.id)
                .save(&state)
                .await;
            return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response();
        }
    };
    let ranked = MockBiometricProvider.search(&image_bytes, candidates, TOP_K);
    for scored in &ranked {
        let _ = crate::db::insert_search_candidate(
            &state.backend,
            &search.id,
            &scored.candidate.id,
            scored.score,
        )
        .await;
    }

    let candidate_rows = match list_search_candidates(&state.backend, &search.id).await {
        Ok(rows) => rows,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };

    AuditRecorder::new(action::SEARCH_COMPLETED, audit_result::SUCCESS, rid)
        .actor(&claims)
        .headers(&headers)
        .case_reference(&case_reference)
        .resource("search", &search.id)
        .metadata(json!({ "candidateCount": candidate_rows.len() }))
        .save(&state)
        .await;

    Json(json!({
        "search": search_json(&search),
        "candidates": candidate_rows.iter().map(search_candidate_json).collect::<Vec<_>>(),
    }))
    .into_response()
}

pub async fn list_searches_route(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rid = request_id(&headers);
    if auth_user_from_headers(&headers, &state.secrets.jwt_secret).is_none() {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    }
    if !require_role(&state, &headers, VIEW_ROLES) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match list_searches(&state.backend).await {
        Ok(rows) => Json(rows.iter().map(search_json).collect::<Vec<_>>()).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn get_search_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    if auth_user_from_headers(&headers, &state.secrets.jwt_secret).is_none() {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    }
    if !require_role(&state, &headers, VIEW_ROLES) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match load_search_by_id(&state.backend, &id).await {
        Ok(Some(search)) => Json(search_json(&search)).into_response(),
        Ok(None) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn get_search_candidates_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    if auth_user_from_headers(&headers, &state.secrets.jwt_secret).is_none() {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    }
    if !require_role(&state, &headers, VIEW_ROLES) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match list_search_candidates(&state.backend, &id).await {
        Ok(rows) => {
            Json(rows.iter().map(search_candidate_json).collect::<Vec<_>>()).into_response()
        }
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn get_candidate_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    if auth_user_from_headers(&headers, &state.secrets.jwt_secret).is_none() {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    }
    if !require_role(&state, &headers, VIEW_ROLES) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match load_candidate_by_id(&state.backend, &id).await {
        Ok(Some(candidate)) => Json(candidate_json(&candidate)).into_response(),
        Ok(None) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewPayload {
    pub search_id: String,
}

/// The one explicit human verification action that can set a candidate's
/// status to "confirmed" within a search — never derived automatically
/// from a similarity score. Restricted to `REVIEWER`/admin roles.
async fn review(
    state: AppState,
    headers: HeaderMap,
    candidate_id: String,
    payload: ReviewPayload,
    status: &str,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !require_role(&state, &headers, REVIEW_ROLES) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }

    let reviewer_name = match load_user_by_id(&state.backend, &claims.id).await {
        Ok(Some(user)) => format!("{} {}", user.first_name, user.last_name)
            .trim()
            .to_string(),
        _ => claims.user_code.clone(),
    };

    match set_search_candidate_status(
        &state.backend,
        &payload.search_id,
        &candidate_id,
        status,
        &claims.id,
        &reviewer_name,
    )
    .await
    {
        Ok(Some(row)) => {
            let event_action = if status == "confirmed" {
                action::CANDIDATE_CONFIRMED
            } else {
                action::CANDIDATE_REJECTED
            };
            AuditRecorder::new(event_action, audit_result::SUCCESS, rid)
                .actor(&claims)
                .headers(&headers)
                .resource("search_candidate", &row.id)
                .metadata(json!({ "searchId": payload.search_id, "candidateId": candidate_id }))
                .save(&state)
                .await;
            Json(search_candidate_json(&row)).into_response()
        }
        Ok(None) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn verify_candidate_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ReviewPayload>,
) -> Response {
    review(state, headers, id, payload, "confirmed").await
}

pub async fn reject_candidate_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ReviewPayload>,
) -> Response {
    review(state, headers, id, payload, "rejected").await
}
