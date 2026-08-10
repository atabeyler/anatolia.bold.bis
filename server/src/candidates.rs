//! Candidate enrollment (madde 1-6): creating candidate records and
//! attaching biometric reference templates to them via the active
//! `BiometricProvider`. Kept separate from `search.rs`, which only ever
//! reads candidates (via `db::CandidateRow`) and records review decisions
//! — this module is the one write path that actually mints new candidate
//! identities and templates.

use axum::extract::{Multipart, Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::{action, result as audit_result, AuditRecorder};
use crate::auth::auth_user_from_headers;
use crate::db::{
    create_candidate, insert_template, list_templates_for_candidate, load_candidate_by_id,
    revoke_template, AppState, BiometricTemplateRow,
};
use crate::entity_resolution::{find_possible_duplicates, DEFAULT_NAME_SIMILARITY_THRESHOLD};
use crate::error::{request_id, ApiError};
use crate::permission;

fn template_json(row: &BiometricTemplateRow) -> serde_json::Value {
    json!({
        "id": row.id,
        "candidateId": row.candidate_id,
        "modelName": row.model_name,
        "modelVersion": row.model_version,
        "embeddingDimension": row.embedding_dimension,
        "qualityScore": row.quality_score,
        "sourceReference": row.source_reference,
        "createdAt": row.created_at,
        "revokedAt": row.revoked_at,
    })
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCandidatePayload {
    pub reference_code: String,
    pub full_name: String,
    pub notes: Option<String>,
}

/// `POST /api/v1/candidates` — creates a bare candidate record with no
/// biometric template attached yet. A reference photo is enrolled
/// separately via `POST /api/v1/candidates/{id}/reference-photos`, since
/// the two can fail independently (a duplicate reference code is a
/// different problem than an unusable reference photo) and an operator
/// may need to retry just the photo step.
pub async fn create_candidate_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateCandidatePayload>,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_manage_candidates(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }

    let reference_code = payload.reference_code.trim().to_string();
    let full_name = payload.full_name.trim().to_string();
    if reference_code.is_empty() || full_name.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    match create_candidate(
        &state.backend,
        &reference_code,
        &full_name,
        payload.notes.as_deref(),
    )
    .await
    {
        Ok(candidate) => {
            // MANDATORY: minting a new candidate identity must never be
            // reported to the client as a clean success if its audit
            // record failed to write — see AuditRecorder::save_mandatory.
            if let Err(mut err) = AuditRecorder::new(
                action::CANDIDATE_CREATED,
                audit_result::SUCCESS,
                rid.clone(),
            )
            .actor(&claims)
            .headers(&headers)
            .resource("candidate", &candidate.id)
            .metadata(json!({ "referenceCode": candidate.reference_code }))
            .save_mandatory(&state)
            .await
            {
                err.request_id = rid;
                return err.into_response();
            }
            Json(json!({
                "id": candidate.id,
                "referenceCode": candidate.reference_code,
                "fullName": candidate.full_name,
                "notes": candidate.notes,
            }))
            .into_response()
        }
        Err(err) => {
            // Duplicate reference_code (UNIQUE constraint) surfaces as a
            // generic sqlx error; there's no portable way to distinguish
            // it from other failures across Postgres/SQLite without
            // parsing driver-specific error codes, so it's reported as a
            // conflict whenever the insert itself failed after passing
            // validation — the only realistic cause in practice.
            tracing::warn!(error = %err, "candidate creation failed");
            ApiError::new("CONFLICT", "errors.candidateReferenceCodeTaken", rid).into_response()
        }
    }
}

/// `POST /api/v1/candidates/{id}/reference-photos` — multipart form field
/// `image`. Runs the active `BiometricProvider`'s enrollment pipeline
/// (detect → quality-gate → align → embed) and stores the resulting
/// template. Under `BIOMETRIC_PROVIDER=mock` this always fails with
/// `BIOMETRIC_PROVIDER_UNAVAILABLE` — the mock provider has no real
/// embedding to enroll.
pub async fn upload_reference_photo_route(
    State(state): State<AppState>,
    Path(candidate_id): Path<String>,
    headers: HeaderMap,
    mut multipart: Multipart,
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

    let mut image_bytes: Option<Vec<u8>> = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => {
                return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response()
            }
        };
        if field.name() == Some("image") {
            image_bytes = field.bytes().await.ok().map(|b| b.to_vec());
        }
    }
    let Some(image_bytes) = image_bytes.filter(|b| !b.is_empty()) else {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    };
    let image_bytes = match crate::image_validation::validate_and_sanitize_probe_image(&image_bytes)
    {
        Ok(sanitized) => sanitized,
        Err(code) => {
            return ApiError::new(code, crate::search::code_message_key(code), rid).into_response()
        }
    };

    let enrollment = match state.biometric_provider.enroll(&image_bytes).await {
        Ok(result) => result,
        Err(err) => {
            tracing::warn!(error = %err, "reference photo enrollment rejected");
            return ApiError::new(err.code(), err.message_key(), rid).into_response();
        }
    };

    match insert_template(
        &state.backend,
        &candidate_id,
        &enrollment.model_name,
        &enrollment.model_version,
        &enrollment.embedding,
        enrollment.quality_score,
        None,
    )
    .await
    {
        Ok(Some(template)) => {
            // MANDATORY: minting a new biometric template must never be
            // reported as a clean success if its audit record failed to
            // write.
            if let Err(mut err) = AuditRecorder::new(
                action::CANDIDATE_REFERENCE_PHOTO_ENROLLED,
                audit_result::SUCCESS,
                rid.clone(),
            )
            .actor(&claims)
            .headers(&headers)
            .resource("candidate", &candidate_id)
            .metadata(json!({
                "templateId": template.id,
                "modelName": template.model_name,
                "modelVersion": template.model_version,
                "qualityScore": template.quality_score,
            }))
            .save_mandatory(&state)
            .await
            {
                err.request_id = rid;
                return err.into_response();
            }
            Json(template_json(&template)).into_response()
        }
        _ => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

/// `GET /api/v1/candidates/{id}/templates` — every template ever enrolled
/// for this candidate, including revoked ones, newest first.
pub async fn list_templates_route(
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
    match list_templates_for_candidate(&state.backend, &candidate_id).await {
        Ok(rows) => Json(json!({
            "items": rows.iter().map(template_json).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

/// `POST /api/v1/candidates/{id}/templates/{template_id}/revoke` — a
/// revoked template is excluded from every future search
/// (`db::list_active_templates` filters `revoked_at IS NULL`) but its row
/// is kept, not deleted, for audit/history purposes.
pub async fn revoke_template_route(
    State(state): State<AppState>,
    Path((candidate_id, template_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !permission::can_manage_candidates(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match revoke_template(&state.backend, &template_id).await {
        Ok(true) => {
            // MANDATORY: revoking a template must never be reported as a
            // clean success if its audit record failed to write — a
            // future search must be able to trust that a "revoked"
            // response really was recorded.
            if let Err(mut err) = AuditRecorder::new(
                action::CANDIDATE_TEMPLATE_REVOKED,
                audit_result::SUCCESS,
                rid.clone(),
            )
            .actor(&claims)
            .headers(&headers)
            .resource("candidate", &candidate_id)
            .metadata(json!({ "templateId": template_id }))
            .save_mandatory(&state)
            .await
            {
                err.request_id = rid;
                return err.into_response();
            }
            Json(json!({ "revoked": true })).into_response()
        }
        Ok(false) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

/// `GET /api/v1/candidates/{id}/possible-duplicates` — conservative
/// entity resolution over non-biometric signals (name similarity, shared
/// OSINT evidence URLs — see `entity_resolution.rs`). Advisory only: it
/// never merges or auto-links candidate records, it only surfaces other
/// candidates a human reviewer may want to compare.
pub async fn possible_duplicates_route(
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
    match find_possible_duplicates(
        &state.backend,
        &candidate_id,
        DEFAULT_NAME_SIMILARITY_THRESHOLD,
    )
    .await
    {
        Ok(matches) => Json(json!({
            "items": matches.iter().map(|m| json!({
                "candidateId": m.candidate.id,
                "referenceCode": m.candidate.reference_code,
                "fullName": m.candidate.full_name,
                "nameSimilarity": m.name_similarity,
                "sharedEvidenceUrls": m.shared_evidence_urls,
            })).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}
