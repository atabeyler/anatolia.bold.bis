//! Organization/unit administration endpoints (madde 12-13). Deliberately
//! separate from `admin.rs`: managing the organization structure itself
//! is a narrower, cross-organization concern than ordinary user
//! administration — see `permission::can_manage_organizations` (only
//! `SYSTEM_ADMIN`, not `SECURITY_ADMIN`).

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::audit::{action, result as audit_result, AuditRecorder};
use crate::auth::auth_user_from_headers;
use crate::db::{
    assign_membership, create_organization, create_organization_unit, list_organization_units,
    list_organizations, remove_membership, AppState,
};
use crate::error::{request_id, ApiError};
use crate::permission;

fn require_org_admin(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    match auth_user_from_headers(headers, &state.secrets.jwt_secret) {
        Some(claims) if permission::can_manage_organizations(&claims.role) => None,
        _ => Some(
            ApiError::new("FORBIDDEN", "errors.forbidden", request_id(headers)).into_response(),
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateOrganizationPayload {
    pub name: String,
}

pub async fn create_organization_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateOrganizationPayload>,
) -> Response {
    if let Some(denied) = require_org_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    let name = payload.name.trim();
    if name.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }
    match create_organization(&state.backend, name).await {
        Ok(org) => {
            AuditRecorder::new(
                action::ORGANIZATION_CREATED,
                audit_result::SUCCESS,
                rid.clone(),
            )
            .actor_opt(auth_user_from_headers(&headers, &state.secrets.jwt_secret).as_ref())
            .headers(&headers)
            .resource("organization", &org.id)
            .save(&state)
            .await;
            Json(org).into_response()
        }
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn list_organizations_route(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Some(denied) = require_org_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    match list_organizations(&state.backend).await {
        Ok(orgs) => Json(orgs).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateUnitPayload {
    pub name: String,
    #[serde(rename = "parentUnitId")]
    pub parent_unit_id: Option<String>,
}

pub async fn create_unit_route(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CreateUnitPayload>,
) -> Response {
    if let Some(denied) = require_org_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    let name = payload.name.trim();
    if name.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }
    match create_organization_unit(
        &state.backend,
        &organization_id,
        payload.parent_unit_id.as_deref(),
        name,
    )
    .await
    {
        Ok(Some(unit)) => {
            AuditRecorder::new(
                action::ORGANIZATION_UNIT_CREATED,
                audit_result::SUCCESS,
                rid.clone(),
            )
            .actor_opt(auth_user_from_headers(&headers, &state.secrets.jwt_secret).as_ref())
            .headers(&headers)
            .resource("organization_unit", &unit.id)
            .save(&state)
            .await;
            Json(unit).into_response()
        }
        Ok(None) => ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn list_units_route(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(denied) = require_org_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    match list_organization_units(&state.backend, &organization_id).await {
        Ok(units) => Json(units).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignMembershipPayload {
    pub user_id: String,
    pub organization_id: String,
    pub organization_unit_id: Option<String>,
}

/// `POST /api/v1/admin/memberships` — assigns a user to an organization
/// (and, optionally, a specific unit within it). This is the only place
/// an organization id is ever attached to a user — always chosen here by
/// an explicitly-authorized administrator, never accepted from the
/// member themselves (madde 13).
pub async fn assign_membership_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AssignMembershipPayload>,
) -> Response {
    if let Some(denied) = require_org_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    match assign_membership(
        &state.backend,
        &payload.user_id,
        &payload.organization_id,
        payload.organization_unit_id.as_deref(),
    )
    .await
    {
        Ok(()) => {
            AuditRecorder::new(
                action::MEMBERSHIP_ASSIGNED,
                audit_result::SUCCESS,
                rid.clone(),
            )
            .actor_opt(auth_user_from_headers(&headers, &state.secrets.jwt_secret).as_ref())
            .headers(&headers)
            .resource("user", &payload.user_id)
            .metadata(json!({ "organizationId": payload.organization_id }))
            .save(&state)
            .await;
            Json(json!({ "messageKey": "admin.org.membershipAssigned" })).into_response()
        }
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveMembershipPayload {
    pub user_id: String,
    pub organization_id: String,
}

pub async fn remove_membership_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RemoveMembershipPayload>,
) -> Response {
    if let Some(denied) = require_org_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    match remove_membership(&state.backend, &payload.user_id, &payload.organization_id).await {
        Ok(()) => {
            AuditRecorder::new(
                action::MEMBERSHIP_REMOVED,
                audit_result::SUCCESS,
                rid.clone(),
            )
            .actor_opt(auth_user_from_headers(&headers, &state.secrets.jwt_secret).as_ref())
            .headers(&headers)
            .resource("user", &payload.user_id)
            .metadata(json!({ "organizationId": payload.organization_id }))
            .save(&state)
            .await;
            Json(json!({ "messageKey": "admin.org.membershipRemoved" })).into_response()
        }
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}
