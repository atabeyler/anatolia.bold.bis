use axum::extract::{Multipart, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::{action, result as audit_result, AuditRecorder};
use crate::auth::{auth_user_from_headers, require_role, Claims};
use crate::db::{
    create_queued_search, finalize_queued_search, list_search_candidates, list_searches_page,
    list_verification_events, load_candidate_by_id, load_search_by_id, load_user_by_id,
    mark_queued_search_failed, record_review_decision, set_search_external_evidence_status,
    AppState, CandidateRow, ReviewDecisionOutcome, SearchCandidateRow, SearchRow,
    VerificationEventRow,
};
use crate::error::{request_id, ApiError};
use crate::evidence::collect_and_store_candidate_evidence;
use crate::osint::query_builder;
use crate::permission;

const DEFAULT_PAGE_SIZE: i64 = 50;

fn search_json(search: &SearchRow) -> serde_json::Value {
    // `external_evidence_status` is stored as an opaque, already-shaped
    // JSON string (see `search::run_auto_osint`) — parsed back into a
    // value here rather than re-serialized field by field. `null` (not
    // an object with all-"not_configured" slots) is the honest
    // representation of "automatic OSINT hasn't reported an outcome for
    // this search yet" — either the feature is off, or its background
    // work (which runs after the search itself is marked `completed`)
    // just hasn't finished.
    let external_evidence_status = search
        .external_evidence_status
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok());
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
        "organizationId": search.organization_id,
        "externalEvidenceStatus": external_evidence_status,
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
/// `image`, optional `topK`. Async search flow: validates
/// the probe image and request synchronously (fast — no biometric
/// inference yet), writes a `queued` search row, and returns
/// **`202 Accepted`** with that row's id immediately. The (potentially
/// slow, especially under `BIOMETRIC_PROVIDER=onnx`) biometric pipeline
/// then runs in a background task; the caller polls
/// `GET /api/v1/search/{id}/status` until `status` leaves
/// `queued`/`processing`. This changed response contract (`202` instead
/// of a synchronous `200` with the finished result) was a deliberate
/// choice made with the repository owner over the simpler
/// `200`-with-full-result shape the search endpoint used before — see
/// `docs/SECURITY_ARCHITECTURE.md`.
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
    // Server-derived only — never accepted from the client. See
    // permission::can_view_scoped_resource.
    let organization_id = crate::db::primary_organization_id(&state.backend, &claims.id)
        .await
        .ok()
        .flatten();

    let queued = match create_queued_search(
        &state.backend,
        &case_reference,
        &purpose,
        &claims.id,
        &requester_name,
        latitude,
        longitude,
        top_k,
        organization_id.as_deref(),
    )
    .await
    {
        Ok(search) => search,
        Err(err) => {
            tracing::warn!(error = %err, "failed to persist queued search");
            AuditRecorder::new(action::SEARCH_FAILED, audit_result::FAILURE, rid.clone())
                .actor(&claims)
                .headers(&headers)
                .case_reference(&case_reference)
                .resource("search", "unknown")
                .save(&state)
                .await;
            return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response();
        }
    };

    // Best-effort: this only records that a search was accepted for
    // processing, nothing security-critical has happened yet — the
    // MANDATORY guarantee (never report success if the audit write
    // failed) is applied to SEARCH_COMPLETED in the background task
    // below instead, since that's the point a client-visible "completed"
    // status becomes trustworthy or not.
    AuditRecorder::new(action::SEARCH_CREATED, audit_result::SUCCESS, rid.clone())
        .actor(&claims)
        .headers(&headers)
        .case_reference(&case_reference)
        .resource("search", &queued.id)
        .metadata(json!({ "topK": top_k }))
        .save(&state)
        .await;

    tokio::spawn(run_queued_search(
        state,
        queued.id.clone(),
        image_bytes,
        top_k,
        claims,
        headers,
        case_reference,
    ));

    (
        axum::http::StatusCode::ACCEPTED,
        Json(json!({ "search": search_json(&queued) })),
    )
        .into_response()
}

/// The background half of the async search flow — runs after
/// `create_search_route` has already returned `202 Accepted` to the
/// client, so there is no HTTP response left to attach a failure to;
/// every outcome is instead written to the search row itself (which
/// `GET /api/v1/search/{id}/status` reports) and to the audit trail.
async fn run_queued_search(
    state: AppState,
    search_id: String,
    image_bytes: Vec<u8>,
    top_k: i64,
    claims: Claims,
    headers: HeaderMap,
    case_reference: String,
) {
    let rid = uuid::Uuid::new_v4().to_string();
    let provider_started = std::time::Instant::now();
    let ranked = match state
        .biometric_provider
        .search(&state, &image_bytes, top_k as usize)
        .await
    {
        Ok(ranked) => {
            metrics::histogram!("biometric_search_duration_seconds")
                .record(provider_started.elapsed().as_secs_f64());
            metrics::counter!("biometric_search_outcomes_total", "outcome" => "success")
                .increment(1);
            ranked
        }
        Err(err) => {
            metrics::counter!(
                "biometric_search_outcomes_total",
                "outcome" => "rejected",
                "code" => err.code(),
            )
            .increment(1);
            tracing::warn!(error = %err, "biometric provider rejected probe image");
            let _ = mark_queued_search_failed(
                &state.backend,
                &search_id,
                err.code(),
                err.message_key(),
            )
            .await;
            AuditRecorder::new(action::SEARCH_FAILED, audit_result::FAILURE, rid)
                .actor(&claims)
                .headers(&headers)
                .case_reference(&case_reference)
                .resource("search", &search_id)
                .metadata(json!({ "failureCode": err.code() }))
                .save(&state)
                .await;
            return;
        }
    };
    let scored: Vec<(String, f64)> = ranked
        .iter()
        .map(|s| (s.candidate.id.clone(), s.score))
        .collect();

    match finalize_queued_search(&state.backend, &search_id, &scored).await {
        Ok(Some(search)) => {
            let candidate_count = list_search_candidates(&state.backend, &search.id)
                .await
                .map(|rows| rows.len())
                .unwrap_or(0);

            // MANDATORY: never leave a search reporting `completed` via
            // the status endpoint if its audit record failed to write —
            // the async equivalent of `save_mandatory`'s guarantee on the
            // old synchronous path. Here there's no HTTP response to
            // fail instead, so a write failure downgrades the search
            // itself to `failed` so a poller never observes a silent lie.
            if let Err(err) =
                AuditRecorder::new(action::SEARCH_COMPLETED, audit_result::SUCCESS, rid.clone())
                    .actor(&claims)
                    .headers(&headers)
                    .case_reference(&case_reference)
                    .resource("search", &search.id)
                    .metadata(json!({ "candidateCount": candidate_count, "topK": top_k }))
                    .save_mandatory(&state)
                    .await
            {
                tracing::error!(error_code = err.code, search_id = %search.id, "mandatory audit write failed after search completed; downgrading to failed");
                let _ = mark_queued_search_failed(
                    &state.backend,
                    &search.id,
                    "AUDIT_WRITE_FAILED",
                    "errors.auditWriteFailed",
                )
                .await;
            } else {
                // Runs after the search itself is already `completed` —
                // see this function's doc comment and `run_auto_osint`'s.
                // A failure anywhere in here must never change the
                // search's own status; it only ever writes the separate
                // `external_evidence_status` field and its own audit
                // trail.
                run_auto_osint(&state, &search, &claims, &headers).await;
            }
        }
        Ok(None) => {
            tracing::error!(search_id = %search_id, "finalize_queued_search found no matching queued row");
        }
        Err(err) => {
            tracing::warn!(error = %err, "search finalization failed; marking search failed");
            let _ = mark_queued_search_failed(
                &state.backend,
                &search_id,
                "SEARCH_PERSIST_FAILED",
                "errors.internal",
            )
            .await;
            AuditRecorder::new(action::SEARCH_FAILED, audit_result::FAILURE, rid)
                .actor(&claims)
                .headers(&headers)
                .case_reference(&case_reference)
                .resource("search", &search_id)
                .save(&state)
                .await;
        }
    }
}

/// `AUTO_OSINT_AFTER_BIOMETRIC_SEARCH`'s entry point — runs once a search
/// has finished its biometric phase and is already `completed`. Takes the
/// search's top-scoring candidates (capped at `osint_auto_max_candidates`),
/// builds a query from each candidate's full name
/// (`osint::query_builder::build_query`), and runs `collect_web_and_news`
/// against it — deliberately never the `AuthorizedSocialProvider` or any
/// reverse-image capability (see `EvidenceOrchestrator::collect_web_and_news`'s
/// doc comment). Every candidate's collection runs concurrently so total
/// wall-clock time stays close to one candidate's worth of provider
/// round-trips rather than the sum across all of them. A provider error
/// never touches `search.status` — only the separate
/// `external_evidence_status` column and the `OSINT_AUTO_*` audit trail.
async fn run_auto_osint(
    state: &AppState,
    search: &SearchRow,
    claims: &Claims,
    headers: &HeaderMap,
) {
    if !state.auto_osint_after_biometric_search {
        return;
    }
    let candidates = match list_search_candidates(&state.backend, &search.id).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(error = %err, search_id = %search.id, "auto-OSINT: failed to load search candidates");
            return;
        }
    };
    let cap = state.osint_auto_max_candidates.max(0) as usize;
    let eligible: Vec<SearchCandidateRow> = candidates.into_iter().take(cap).collect();

    let auto_rid = uuid::Uuid::new_v4().to_string();
    AuditRecorder::new(
        action::OSINT_AUTO_STARTED,
        audit_result::SUCCESS,
        auto_rid.clone(),
    )
    .actor(claims)
    .headers(headers)
    .resource("search", &search.id)
    .metadata(json!({ "candidateCount": eligible.len() }))
    .save(state)
    .await;

    if eligible.is_empty() {
        let status = json!({
            "web": "unavailable",
            "news": "unavailable",
            "social": "not_configured",
            "reverseImage": "not_configured",
        });
        let _ =
            set_search_external_evidence_status(&state.backend, &search.id, &status.to_string())
                .await;
        AuditRecorder::new(action::OSINT_AUTO_FAILED, audit_result::FAILURE, auto_rid)
            .actor(claims)
            .headers(headers)
            .resource("search", &search.id)
            .metadata(json!({ "reason": "no_eligible_candidates" }))
            .save(state)
            .await;
        return;
    }

    let mut handles = Vec::with_capacity(eligible.len());
    for candidate in eligible {
        let Some(query) = query_builder::build_query(&candidate.candidate_full_name) else {
            continue;
        };
        let task_state = state.clone();
        let candidate_id = candidate.candidate_id;
        let collected_by = claims.id.clone();
        handles.push(tokio::spawn(async move {
            let (web, news) = task_state
                .osint_orchestrator
                .collect_web_and_news(&query)
                .await;
            let web_success = web.iter().filter(|o| o.error.is_none()).count();
            let web_fail = web.len() - web_success;
            let news_success = news.iter().filter(|o| o.error.is_none()).count();
            let news_fail = news.len() - news_success;
            let mut outcomes = web;
            outcomes.extend(news);
            let result = collect_and_store_candidate_evidence(
                &task_state,
                &candidate_id,
                Some(&collected_by),
                &outcomes,
            )
            .await;
            (web_success, web_fail, news_success, news_fail, result)
        }));
    }

    let (mut web_success, mut web_fail, mut news_success, mut news_fail) = (0, 0, 0, 0);
    let mut any_stored = false;
    let mut any_provider_error = false;
    for handle in handles {
        let Ok((ws, wf, ns, nf, result)) = handle.await else {
            continue;
        };
        web_success += ws;
        web_fail += wf;
        news_success += ns;
        news_fail += nf;
        any_stored = any_stored || !result.stored.is_empty();
        any_provider_error = any_provider_error || !result.provider_errors.is_empty();
    }

    let (web_is_mock, news_is_mock) = provider_mock_flags(state);
    let status = json!({
        "web": slot_status(web_is_mock, web_success, web_fail),
        "news": slot_status(news_is_mock, news_success, news_fail),
        // Never attempted by the automatic trigger — see this function's
        // doc comment.
        "social": "not_configured",
        "reverseImage": "not_configured",
    });
    let _ =
        set_search_external_evidence_status(&state.backend, &search.id, &status.to_string()).await;

    let outcome_action = if any_provider_error {
        action::OSINT_AUTO_PARTIAL
    } else {
        action::OSINT_AUTO_COMPLETED
    };
    let outcome_result = if any_provider_error {
        audit_result::FAILURE
    } else {
        audit_result::SUCCESS
    };
    AuditRecorder::new(
        outcome_action,
        outcome_result,
        uuid::Uuid::new_v4().to_string(),
    )
    .actor(claims)
    .headers(headers)
    .resource("search", &search.id)
    .metadata(json!({ "webStored": any_stored, "status": status }))
    .save(state)
    .await;
}

/// Real (non-mock) or mock, for the web-search and news provider slots
/// respectively — read once from the orchestrator's own status reporting
/// rather than re-deriving it from a provider name string.
fn provider_mock_flags(state: &AppState) -> (bool, bool) {
    let mut web_is_mock = false;
    let mut news_is_mock = false;
    for status in state.osint_orchestrator.provider_status() {
        match status.slot {
            "web_search" => web_is_mock = status.is_mock,
            "news" => news_is_mock = status.is_mock,
            _ => {}
        }
    }
    (web_is_mock, news_is_mock)
}

/// A provider slot's status for one automatic-OSINT run: `"mock"` if the
/// slot is running its mock fallback (regardless of outcome — a mock
/// result is never "completed" real evidence); otherwise `"completed"`,
/// `"partial"`, or `"failed"` depending on how many of the (possibly
/// several, one per attempted candidate) calls to it errored.
fn slot_status(is_mock: bool, success: usize, fail: usize) -> &'static str {
    if is_mock {
        return "mock";
    }
    if fail == 0 {
        "completed"
    } else if success == 0 {
        "failed"
    } else {
        "partial"
    }
}

/// `GET /api/v1/search/{search_id}/status` — polling endpoint for the
/// async search flow: the current search row plus its candidates (once
/// any exist). Poll until `search.status` is no longer `queued`/
/// `processing`. Same view-role and object-level authorization as the
/// rest of the search workflow.
pub async fn get_search_status_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_view_search(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    let search = match load_search_by_id(&state.backend, &id).await {
        Ok(Some(search)) => search,
        Ok(None) => return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    let org_ids = actor_org_ids(&state, &claims).await;
    if !permission::can_view_scoped_resource(
        &claims.role,
        &org_ids,
        search.organization_id.as_deref(),
    ) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    let candidate_rows = match list_search_candidates(&state.backend, &search.id).await {
        Ok(rows) => rows,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    Json(json!({
        "search": search_json(&search),
        "candidates": candidate_rows.iter().map(search_candidate_json).collect::<Vec<_>>(),
    }))
    .into_response()
}

pub(crate) fn code_message_key(code: &'static str) -> &'static str {
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
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_view_search(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    // Object-level authorization: SYSTEM_ADMIN sees every
    // organization's searches; everyone else only sees their own
    // organization's (plus any search with no owning organization at
    // all — see db::push_search_org_scope_pg/_sqlite).
    let org_scope = if claims.role == crate::roles::SYSTEM_ADMIN {
        None
    } else {
        crate::db::user_organization_ids(&state.backend, &claims.id)
            .await
            .ok()
    };
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
    match list_searches_page(&state.backend, page, page_size, org_scope.as_deref()).await {
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

/// Resolves the organizations `claims` belongs to (empty for
/// `SYSTEM_ADMIN`, which never needs them — see
/// `permission::can_view_scoped_resource`'s own bypass).
async fn actor_org_ids(state: &AppState, claims: &crate::auth::Claims) -> Vec<String> {
    if claims.role == crate::roles::SYSTEM_ADMIN {
        return Vec::new();
    }
    crate::db::user_organization_ids(&state.backend, &claims.id)
        .await
        .unwrap_or_default()
}

pub async fn get_search_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_view_search(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match load_search_by_id(&state.backend, &id).await {
        Ok(Some(search)) => {
            let org_ids = actor_org_ids(&state, &claims).await;
            if !permission::can_view_scoped_resource(
                &claims.role,
                &org_ids,
                search.organization_id.as_deref(),
            ) {
                return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
            }
            Json(search_json(&search)).into_response()
        }
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
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_view_search(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match load_search_by_id(&state.backend, &id).await {
        Ok(Some(search)) => {
            let org_ids = actor_org_ids(&state, &claims).await;
            if !permission::can_view_scoped_resource(
                &claims.role,
                &org_ids,
                search.organization_id.as_deref(),
            ) {
                return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
            }
        }
        Ok(None) => return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
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
/// status. Same view-role requirement as the rest of the search workflow,
/// plus the same object-level organization scoping.
pub async fn get_candidate_history_route(
    State(state): State<AppState>,
    Path((search_id, candidate_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_view_search(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match load_search_by_id(&state.backend, &search_id).await {
        Ok(Some(search)) => {
            let org_ids = actor_org_ids(&state, &claims).await;
            if !permission::can_view_scoped_resource(
                &claims.role,
                &org_ids,
                search.organization_id.as_deref(),
            ) {
                return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
            }
        }
        Ok(None) => return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
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
            // MANDATORY: a verification decision must never be
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
