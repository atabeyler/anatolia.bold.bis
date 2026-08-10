//! Entity graph endpoints (item 10 in `docs/HARDENING_CHECKLIST.md`):
//! read and manually extend a candidate's entity relations (alias,
//! username, organization, website — see `db::entity_graph`). Kept
//! separate from `candidates.rs`, same reasoning as `evidence.rs`: a
//! distinct capability layered on top of the same candidate identity.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::{action, result as audit_result, AuditRecorder};
use crate::auth::auth_user_from_headers;
use crate::db::{self, is_valid_relation_type, load_candidate_by_id, AppState, EntityRelationRow};
use crate::error::{request_id, ApiError};
use crate::permission;

fn relation_json(row: &EntityRelationRow) -> serde_json::Value {
    json!({
        "id": row.id,
        "candidateId": row.candidate_id,
        "relationType": row.relation_type,
        "value": row.value,
        "evidenceId": row.evidence_id,
        "addedBy": row.added_by,
        "createdAt": row.created_at,
    })
}

/// Checks that the caller may view `candidate`'s data, applying the same
/// organization-scoping rule already established for searches
/// (`permission::can_view_scoped_resource`) — a candidate with no owning
/// organization stays visible to anyone who passes the role check, same
/// as legacy/orgless searches.
async fn authorize_view(
    state: &AppState,
    claims: &crate::auth::Claims,
    candidate: &crate::db::CandidateRow,
) -> bool {
    if !permission::can_view_search(&claims.role) {
        return false;
    }
    let actor_org_ids = db::user_organization_ids(&state.backend, &claims.id)
        .await
        .unwrap_or_default();
    permission::can_view_scoped_resource(
        &claims.role,
        &actor_org_ids,
        candidate.organization_id.as_deref(),
    )
}

/// `GET /api/v1/candidates/{id}/entity-graph` — every non-revoked
/// relation recorded for this candidate (see `db::entity_graph`'s module
/// doc comment for how a relation gets there — automatic for evidence
/// URLs, manual for everything else).
pub async fn entity_graph_route(
    State(state): State<AppState>,
    Path(candidate_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    let Ok(Some(candidate)) = load_candidate_by_id(&state.backend, &candidate_id).await else {
        return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response();
    };
    if !authorize_view(&state, &claims, &candidate).await {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match db::list_relations_for_candidate(&state.backend, &candidate_id).await {
        Ok(rows) => Json(json!({
            "candidateId": candidate.id,
            "items": rows.iter().map(relation_json).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddEntityRelationPayload {
    pub relation_type: String,
    pub value: String,
}

/// `POST /api/v1/candidates/{id}/entity-graph` — a human reviewer records
/// an alias/username/organization/website they found while reviewing this
/// candidate's evidence. Always advisory (see module doc comment): this
/// never merges or auto-links anything, it only records a claim with an
/// attributed author.
pub async fn add_entity_relation_route(
    State(state): State<AppState>,
    Path(candidate_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<AddEntityRelationPayload>,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_manage_candidates(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    let Ok(Some(candidate)) = load_candidate_by_id(&state.backend, &candidate_id).await else {
        return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response();
    };
    if !authorize_view(&state, &claims, &candidate).await {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }

    let relation_type = payload.relation_type.trim().to_lowercase();
    let value = payload.value.trim().to_string();
    if !is_valid_relation_type(&relation_type) || value.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    match db::insert_relation(
        &state.backend,
        &candidate_id,
        &relation_type,
        &value,
        None,
        Some(&claims.id),
    )
    .await
    {
        Ok(Some(row)) => {
            AuditRecorder::new(
                action::CANDIDATE_ENTITY_RELATION_ADDED,
                audit_result::SUCCESS,
                rid,
            )
            .actor(&claims)
            .headers(&headers)
            .resource("candidate", &candidate_id)
            .metadata(json!({ "relationType": relation_type, "value": value }))
            .save(&state)
            .await;
            Json(relation_json(&row)).into_response()
        }
        Ok(None) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}
