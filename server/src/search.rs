use axum::extract::{Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::{action, result as audit_result, AuditRecorder};
use crate::auth::{auth_user_from_headers, require_role};
use crate::biometric::{BiometricProvider, MockBiometricProvider};
use crate::db::{
    create_search_with_candidates, list_candidates, list_search_candidates, list_searches_page,
    list_verification_events, load_candidate_by_id, load_search_by_id, load_user_by_id,
    record_failed_search, record_review_decision, AppState, CandidateRow, ReviewDecisionOutcome,
    SearchCandidateRow, SearchRow, VerificationEventRow,
};
use crate::error::{request_id, ApiError};
use crate::permission;

const DEFAULT_PAGE_SIZE: i64 = 50;

fn search_json(search: &SearchRow) -> serde_json::Value {
    json!({
        "id": search.id,
        "caseReference": search.case_reference,
        "purpose": search.purpose,
        "requestedByName": search.requested_by_name,
        "status": search.status,
        "latitude": search.latitude,
        "longitude": search.longitude,
        "topK": search.top_k,
        "startedAt": search.started_at,
        "completedAt": search.completed_at,
        "failureCode": search.failure_code,
        "failureMessageKey": search.failure_message_key,
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

fn verification_event_json(event: &VerificationEventRow) -> serde_json::Value {
    json!({
        "id": event.id,
        "reviewerName": event.reviewer_name,
        "decision": event.decision,
        "reason": event.reason,
        "notes": event.notes,
        "createdAt": event.created_at,
    })
}

/// `POST /api/v1/search/face` — multipart form: `caseReference`, `purpose`,
/// `image`, optional `topK`. Runs the (currently mock) `BiometricProvider`
/// over every known candidate and stores the ranked, scored result — never
/// a verdict, see CLAUDE.md's "candidates, not verdicts" principle. The
/// search row and every one of its candidate results are written in a
/// single transaction (see `db::create_search_with_candidates`); a
/// persistence failure never leaves a partial candidate list behind, and
/// is itself recorded as a `failed` search (see `db::record_failed_search`)
/// rather than silently vanishing.
pub async fn create_search_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_create_search(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }

    let mut case_reference: Option<String> = None;
    let mut purpose: Option<String> = None;
    let mut image_bytes: Option<Vec<u8>> = None;
    let mut latitude: Option<f64> = None;
    let mut longitude: Option<f64> = None;
    let mut requested_top_k: Option<i64> = None;

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
            "topK" => requested_top_k = field.text().await.ok().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }

    let case_reference = case_reference.unwrap_or_default().trim().to_string();
    let purpose = purpose.unwrap_or_default().trim().to_string();
    let Some(image_bytes) = image_bytes.filter(|b| !b.is_empty()) else {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    };
    let image_bytes = match crate::image_validation::validate_and_sanitize_probe_image(&image_bytes)
    {
        Ok(sanitized) => sanitized,
        Err(code) => return ApiError::new(code, code_message_key(code), rid).into_response(),
    };
    if case_reference.is_empty() || purpose.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }
    // Either both coordinates are present and each within its valid
    // range, or neither is present — one without the other is a
    // malformed capture, not a "coordinate unavailable" case.
    match (latitude, longitude) {
        (Some(lat), Some(lon)) => {
            if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
                return ApiError::new("VALIDATION_ERROR", "errors.invalidCoordinates", rid)
                    .into_response();
            }
        }
        (None, None) => {}
        _ => {
            return ApiError::new("VALIDATION_ERROR", "errors.invalidCoordinates", rid)
                .into_response()
        }
    }

    // A client-requested top-k above the configured ceiling is clamped
    // down, never rejected — see docs/ENVIRONMENT.md's SEARCH_MAX_TOP_K.
    let top_k = requested_top_k
        .filter(|k| *k > 0)
        .unwrap_or(state.search_limits.default_top_k)
        .min(state.search_limits.max_top_k);

    let requester_name = match load_user_by_id(&state.backend, &claims.id).await {
        Ok(Some(user)) => format!("{} {}", user.first_name, user.last_name)
            .trim()
            .to_string(),
        _ => claims.user_code.clone(),
    };

    let candidates = match list_candidates(&state.backend).await {
        Ok(rows) => rows,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    let ranked = MockBiometricProvider.search(&image_bytes, candidates, top_k as usize);
    let scored: Vec<(String, f64)> = ranked
        .iter()
        .map(|s| (s.candidate.id.clone(), s.score))
        .collect();

    match create_search_with_candidates(
        &state.backend,
        &case_reference,
        &purpose,
        &claims.id,
        &requester_name,
        latitude,
        longitude,
        top_k,
        &scored,
    )
    .await
    {
        Ok(search) => {
            let candidate_rows = match list_search_candidates(&state.backend, &search.id).await {
                Ok(rows) => rows,
                Err(_) => {
                    return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response()
                }
            };

            // MANDATORY: a biometric search must never be reported to the
            // client as a clean success if its audit record failed to
            // write — see AuditRecorder::save_mandatory. The search row
            // itself is already committed at this point (this codebase
            // does not yet share one transaction between the two — see
            // the limitation noted on save_mandatory); what this
            // guarantees is that the API response is never a silent lie.
            if let Err(mut err) =
                AuditRecorder::new(action::SEARCH_COMPLETED, audit_result::SUCCESS, rid.clone())
                    .actor(&claims)
                    .headers(&headers)
                    .case_reference(&case_reference)
                    .resource("search", &search.id)
                    .metadata(json!({ "candidateCount": candidate_rows.len(), "topK": top_k }))
                    .save_mandatory(&state)
                    .await
            {
                err.request_id = rid;
                return err.into_response();
            }

            Json(json!({
                "search": search_json(&search),
                "candidates": candidate_rows.iter().map(search_candidate_json).collect::<Vec<_>>(),
            }))
            .into_response()
        }
        Err(err) => {
            tracing::warn!(error = %err, "search persistence failed; rolled back");
            let failed = record_failed_search(
                &state.backend,
                &case_reference,
                &purpose,
                &claims.id,
                &requester_name,
                latitude,
                longitude,
                top_k,
                "SEARCH_PERSIST_FAILED",
                "errors.internal",
            )
            .await
            .ok()
            .flatten();

            AuditRecorder::new(action::SEARCH_FAILED, audit_result::FAILURE, rid.clone())
                .actor(&claims)
                .headers(&headers)
                .case_reference(&case_reference)
                .resource(
                    "search",
                    failed.as_ref().map(|s| s.id.as_str()).unwrap_or("unknown"),
                )
                .save(&state)
                .await;

            ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response()
        }
    }
}

fn code_message_key(code: &'static str) -> &'static str {
    match code {
        "IMAGE_TOO_LARGE" => "errors.imageTooLarge",
        "UNSUPPORTED_IMAGE_TYPE" => "errors.unsupportedImageType",
        "IMAGE_DECODE_FAILED" => "errors.imageDecodeFailed",
        "IMAGE_DIMENSIONS_INVALID" => "errors.imageDimensionsInvalid",
        _ => "errors.validation",
    }
}

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub page: Option<i64>,
    #[serde(rename = "pageSize")]
    pub page_size: Option<i64>,
}

pub async fn list_searches_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> Response {
    let rid = request_id(&headers);
    if auth_user_from_headers(&headers, &state.secrets.jwt_secret).is_none() {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    }
    if !require_role(&state, &headers, permission::can_view_search) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
    match list_searches_page(&state.backend, page, page_size).await {
        Ok((rows, total)) => Json(json!({
            "items": rows.iter().map(search_json).collect::<Vec<_>>(),
            "page": page,
            "pageSize": page_size.clamp(1, 200),
            "total": total,
        }))
        .into_response(),
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
    if !require_role(&state, &headers, permission::can_view_search) {
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
    if !require_role(&state, &headers, permission::can_view_search) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match list_search_candidates(&state.backend, &id).await {
        Ok(rows) => {
            Json(rows.iter().map(search_candidate_json).collect::<Vec<_>>()).into_response()
        }
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

/// `GET /api/v1/search/{search_id}/candidates/{candidate_id}/history` — the
/// full, immutable review history for one candidate within one search
/// (every `verification_events` row, oldest first) — not just the current
/// status. Same view-role requirement as the rest of the search workflow.
pub async fn get_candidate_history_route(
    State(state): State<AppState>,
    Path((search_id, candidate_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    if auth_user_from_headers(&headers, &state.secrets.jwt_secret).is_none() {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    }
    if !require_role(&state, &headers, permission::can_view_search) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    let candidates = match list_search_candidates(&state.backend, &search_id).await {
        Ok(rows) => rows,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    let Some(search_candidate) = candidates
        .into_iter()
        .find(|row| row.candidate_id == candidate_id)
    else {
        return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response();
    };
    match list_verification_events(&state.backend, &search_candidate.id).await {
        Ok(events) => Json(
            events
                .iter()
                .map(verification_event_json)
                .collect::<Vec<_>>(),
        )
        .into_response(),
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
    if !require_role(&state, &headers, permission::can_view_search) {
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
    pub reason: Option<String>,
    pub notes: Option<String>,
}

/// The one explicit human verification action that can set a candidate's
/// status to "confirmed" within a search — never derived automatically
/// from a similarity score. Restricted to `REVIEWER`/admin roles. Every
/// call appends a new `verification_events` row rather than overwriting
/// the previous decision — see `db::record_review_decision`.
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
    if !require_role(&state, &headers, permission::can_review_candidate) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }

    let reviewer_name = match load_user_by_id(&state.backend, &claims.id).await {
        Ok(Some(user)) => format!("{} {}", user.first_name, user.last_name)
            .trim()
            .to_string(),
        _ => claims.user_code.clone(),
    };

    match record_review_decision(
        &state.backend,
        &payload.search_id,
        &candidate_id,
        status,
        &claims.id,
        &reviewer_name,
        payload.reason.as_deref(),
        payload.notes.as_deref(),
        &rid,
        state.require_second_review,
    )
    .await
    {
        Ok(ReviewDecisionOutcome::Applied(row)) => {
            let event_action = match status {
                "confirmed" if row.status == "needs_second_review" => {
                    action::CANDIDATE_FIRST_REVIEW_RECORDED
                }
                "rejected" if row.status == "needs_second_review" => {
                    action::CANDIDATE_FIRST_REVIEW_RECORDED
                }
                "confirmed" => action::CANDIDATE_CONFIRMED,
                "inconclusive" => action::CANDIDATE_MARKED_INCONCLUSIVE,
                _ => action::CANDIDATE_REJECTED,
            };
            // MANDATORY: a verification decision (madde 17) must never be
            // reported as successful if its audit trail entry failed to
            // write — see AuditRecorder::save_mandatory.
            if let Err(mut err) =
                AuditRecorder::new(event_action, audit_result::SUCCESS, rid.clone())
                    .actor(&claims)
                    .headers(&headers)
                    .resource("search_candidate", &row.id)
                    .metadata(json!({ "searchId": payload.search_id, "candidateId": candidate_id }))
                    .save_mandatory(&state)
                    .await
            {
                err.request_id = rid;
                return err.into_response();
            }
            Json(search_candidate_json(&row)).into_response()
        }
        Ok(ReviewDecisionOutcome::NotFound) => {
            ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response()
        }
        Ok(ReviewDecisionOutcome::SameReviewerForbidden) => {
            AuditRecorder::new(
                action::CANDIDATE_SECOND_REVIEW_DENIED,
                audit_result::DENIED,
                rid.clone(),
            )
            .actor(&claims)
            .headers(&headers)
            .metadata(json!({ "searchId": payload.search_id, "candidateId": candidate_id }))
            .save(&state)
            .await;
            ApiError::new(
                "SAME_REVIEWER_FORBIDDEN",
                "errors.sameReviewerForbidden",
                rid,
            )
            .into_response()
        }
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

/// Neither a positive nor a negative identification — the reviewer looked
/// at the candidate and could not reach a confident decision either way
/// (poor image quality, ambiguous similarity, insufficient context).
/// Distinct from simply not reviewing yet (`pending`): this is itself a
/// recorded decision, just one that leaves the candidate open rather than
/// closing it out as confirmed or rejected.
pub async fn mark_candidate_inconclusive_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<ReviewPayload>,
) -> Response {
    review(state, headers, id, payload, "inconclusive").await
}
