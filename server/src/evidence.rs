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
use crate::candidates::authorize_candidate_scope;
use crate::db::{
    insert_evidence, list_evidence_for_candidate, load_candidate_by_id, AppState, EvidenceRow,
};
use crate::error::{request_id, ApiError};
use crate::osint::ProviderOutcome;
use crate::permission;

/// Result of running one or more OSINT providers against a candidate and
/// persisting whatever came back — shared by the manual
/// `POST /candidates/{id}/evidence/collect` route and the automatic
/// biometric-search trigger (`search::run_queued_search`), so there is
/// exactly one place that turns provider outcomes into stored evidence.
pub struct CollectedEvidence {
    pub stored: Vec<EvidenceRow>,
    pub provider_errors: Vec<serde_json::Value>,
}

/// Runs `outcomes` (already-collected provider results — see
/// `osint::EvidenceOrchestrator::collect`/`collect_web_and_news`) against
/// `candidate_id` and persists each successful item, skipping any item
/// that duplicates one already stored for this candidate.
///
/// Deduplication key: `(provider_name, normalized_url)` when the item has
/// a URL (lowercased, trailing slash trimmed — good enough to catch a
/// provider returning the same link twice across repeated collection
/// runs, not a general URL-canonicalization library); `(provider_name,
/// title)` otherwise, since a provider that never sets a URL (e.g. a
/// social profile match) still shouldn't be stored twice for an
/// identical title. This is checked against *every* evidence item already
/// on the candidate, not just ones from the same run — re-running manual
/// "Collect Evidence" (or the automatic trigger firing again on a repeat
/// search) must not keep re-inserting the same item.
pub async fn collect_and_store_candidate_evidence(
    state: &AppState,
    candidate_id: &str,
    collected_by: Option<&str>,
    outcomes: &[ProviderOutcome],
) -> CollectedEvidence {
    let existing = list_evidence_for_candidate(&state.backend, candidate_id)
        .await
        .unwrap_or_default();
    let mut seen: std::collections::HashSet<(String, String)> = existing
        .iter()
        .map(|row| (row.provider_name.clone(), dedupe_key(&row.url, &row.title)))
        .collect();

    let mut stored = Vec::new();
    let mut provider_errors = Vec::new();
    for outcome in outcomes {
        if let Some(error) = &outcome.error {
            provider_errors.push(serde_json::json!({
                "provider": outcome.provider_name,
                "error": error,
            }));
            continue;
        }
        for item in &outcome.items {
            let key = (
                item.provider_name.clone(),
                dedupe_key(&item.url, &item.title),
            );
            if !seen.insert(key) {
                continue;
            }
            if let Ok(Some(row)) =
                insert_evidence(&state.backend, candidate_id, item, collected_by).await
            {
                stored.push(row);
            }
        }
    }

    CollectedEvidence {
        stored,
        provider_errors,
    }
}

fn dedupe_key(url: &Option<String>, title: &str) -> String {
    match url {
        Some(url) if !url.trim().is_empty() => {
            format!(
                "url:{}",
                url.trim().to_ascii_lowercase().trim_end_matches('/')
            )
        }
        _ => format!("title:{}", title.trim().to_ascii_lowercase()),
    }
}

fn evidence_json(row: &EvidenceRow) -> serde_json::Value {
    let title_params: Option<serde_json::Value> = row
        .title_params
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok());
    let details: Vec<serde_json::Value> = row
        .details
        .as_deref()
        .and_then(|raw| serde_json::from_str(raw).ok())
        .unwrap_or_default();
    json!({
        "id": row.id,
        "candidateId": row.candidate_id,
        "sourceType": row.source_type,
        "providerName": row.provider_name,
        "title": row.title,
        "titleKey": row.title_key,
        "titleParams": title_params,
        "url": row.url,
        "snippet": row.snippet,
        "details": details,
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

    let candidate = match load_candidate_by_id(&state.backend, &candidate_id).await {
        Ok(Some(candidate)) => candidate,
        Ok(None) => return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    if !authorize_candidate_scope(&state, &claims, &candidate).await {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }

    let query = payload.query.trim().to_string();
    if query.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let outcomes = state.osint_orchestrator.collect(&query).await;
    let CollectedEvidence {
        stored,
        provider_errors,
    } = collect_and_store_candidate_evidence(&state, &candidate_id, Some(&claims.id), &outcomes)
        .await;

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
    let Ok(Some(candidate)) = load_candidate_by_id(&state.backend, &candidate_id).await else {
        return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response();
    };
    if !authorize_candidate_scope(&state, &claims, &candidate).await {
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
