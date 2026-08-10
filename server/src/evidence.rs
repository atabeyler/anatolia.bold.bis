//! Evidence collection endpoints (P2 OSINT appendix): runs the active
//! `EvidenceOrchestrator` against a candidate's identifying details and
//! stores whatever each provider returns. Kept separate from
//! `candidates.rs` since this is a distinct capability (non-biometric
//! evidence gathering) layered on top of the same candidate identity.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::{action, result as audit_result, AuditRecorder};
use crate::auth::auth_user_from_headers;
use crate::db::{
    insert_evidence, list_evidence_for_candidate, load_candidate_by_id, AppState, EvidenceRow,
};
use crate::error::{request_id, ApiError};
use crate::permission;

fn evidence_json(row: &EvidenceRow) -> serde_json::Value {
    json!({
        "id": row.id,
        "candidateId": row.candidate_id,
        "sourceType": row.source_type,
        "providerName": row.provider_name,
        "title": row.title,
        "url": row.url,
        "snippet": row.snippet,
        "confidenceScore": row.confidence_score,
        "collectedBy": row.collected_by,
        "createdAt": row.created_at,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectEvidencePayload {
    pub query: String,
}

/// `POST /api/v1/candidates/{id}/evidence/collect` — runs every
/// configured OSINT provider against `query` (typically the candidate's
/// full name or another identifying string the operator supplies) and
/// persists whatever each provider returns. A provider that fails does
/// not fail the whole request — see `osint::EvidenceOrchestrator::collect`
/// — its failure is reported per-provider in the response instead.
pub async fn collect_evidence_route(
    State(state): State<AppState>,
    Path(candidate_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CollectEvidencePayload>,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_manage_candidates(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }

    match load_candidate_by_id(&state.backend, &candidate_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }

    let query = payload.query.trim().to_string();
    if query.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let outcomes = state.osint_orchestrator.collect(&query).await;

    let mut stored = Vec::new();
    let mut provider_errors = Vec::new();
    for outcome in &outcomes {
        if let Some(error) = &outcome.error {
            provider_errors.push(json!({ "provider": outcome.provider_name, "error": error }));
            continue;
        }
        for item in &outcome.items {
            if let Ok(Some(row)) =
                insert_evidence(&state.backend, &candidate_id, item, Some(&claims.id)).await
            {
                stored.push(row);
            }
        }
    }

    AuditRecorder::new(
        action::CANDIDATE_EVIDENCE_COLLECTED,
        audit_result::SUCCESS,
        rid.clone(),
    )
    .actor(&claims)
    .headers(&headers)
    .resource("candidate", &candidate_id)
    .metadata(json!({
        "query": query,
        "itemsStored": stored.len(),
        "providerErrors": provider_errors,
    }))
    .save(&state)
    .await;

    Json(json!({
        "items": stored.iter().map(evidence_json).collect::<Vec<_>>(),
        "providerErrors": provider_errors,
    }))
    .into_response()
}

/// `GET /api/v1/candidates/{id}/evidence` — every evidence item collected
/// for this candidate, newest first.
pub async fn list_evidence_route(
    State(state): State<AppState>,
    Path(candidate_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_view_search(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match list_evidence_for_candidate(&state.backend, &candidate_id).await {
        Ok(rows) => Json(json!({
            "items": rows.iter().map(evidence_json).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}
