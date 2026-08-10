//! Central audit trail. Every security- or case-relevant action goes
//! through `AuditRecorder` instead of a handler writing its own ad-hoc
//! `INSERT INTO audit_events` — that keeps the shape of what gets
//! recorded (and, just as importantly, what never does: passwords,
//! tokens, national IDs, raw biometric data) in one place. See
//! `db::audit_events` for the storage layer and CLAUDE.md for the
//! append-only requirement (no handler ever calls UPDATE/DELETE here).

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::auth::{require_role, Claims};
use crate::db::{
    insert_audit_event, list_audit_events, verify_chain, AppState, AuditEventFilter, AuditEventRow,
    NewAuditEvent,
};
use crate::error::{request_id, ApiError};
use crate::permission;

pub mod action {
    // Auth
    pub const AUTH_LOGIN_SUCCESS: &str = "AUTH_LOGIN_SUCCESS";
    pub const AUTH_LOGIN_FAILED: &str = "AUTH_LOGIN_FAILED";
    pub const AUTH_REFRESH_SUCCESS: &str = "AUTH_REFRESH_SUCCESS";
    pub const AUTH_REFRESH_FAILED: &str = "AUTH_REFRESH_FAILED";
    pub const AUTH_LOGOUT: &str = "AUTH_LOGOUT";
    pub const AUTH_LOGOUT_ALL: &str = "AUTH_LOGOUT_ALL";
    pub const AUTH_SESSION_REVOKED: &str = "AUTH_SESSION_REVOKED";
    pub const AUTH_TOKEN_REUSE_DETECTED: &str = "AUTH_TOKEN_REUSE_DETECTED";
    pub const AUTH_PASSWORD_RESET_REQUESTED: &str = "AUTH_PASSWORD_RESET_REQUESTED";
    pub const AUTH_PASSWORD_RESET_COMPLETED: &str = "AUTH_PASSWORD_RESET_COMPLETED";

    // MFA
    pub const MFA_ENABLED: &str = "MFA_ENABLED";
    pub const MFA_DISABLED: &str = "MFA_DISABLED";
    pub const MFA_CHALLENGE_FAILED: &str = "MFA_CHALLENGE_FAILED";
    pub const MFA_RECOVERY_CODE_USED: &str = "MFA_RECOVERY_CODE_USED";
    pub const MFA_RESET_BY_ADMIN: &str = "MFA_RESET_BY_ADMIN";

    // Registration
    pub const REGISTRATION_CREATED: &str = "REGISTRATION_CREATED";
    pub const REGISTRATION_APPROVED: &str = "REGISTRATION_APPROVED";
    pub const REGISTRATION_REJECTED: &str = "REGISTRATION_REJECTED";

    // User administration
    pub const USER_CREATED: &str = "USER_CREATED";
    pub const USER_UPDATED: &str = "USER_UPDATED";
    pub const USER_BANNED: &str = "USER_BANNED";
    pub const USER_UNBANNED: &str = "USER_UNBANNED";
    pub const USER_DELETED: &str = "USER_DELETED";
    pub const USER_ROLE_CHANGED: &str = "USER_ROLE_CHANGED";

    // Search / biometric workflow
    pub const SEARCH_CREATED: &str = "SEARCH_CREATED";
    pub const SEARCH_COMPLETED: &str = "SEARCH_COMPLETED";
    pub const SEARCH_FAILED: &str = "SEARCH_FAILED";
    pub const CANDIDATE_CONFIRMED: &str = "CANDIDATE_CONFIRMED";
    pub const CANDIDATE_REJECTED: &str = "CANDIDATE_REJECTED";
    pub const CANDIDATE_MARKED_INCONCLUSIVE: &str = "CANDIDATE_MARKED_INCONCLUSIVE";
    // Four-eyes review (madde 15) — only emitted when REQUIRE_SECOND_REVIEW=true.
    pub const CANDIDATE_FIRST_REVIEW_RECORDED: &str = "CANDIDATE_FIRST_REVIEW_RECORDED";
    pub const CANDIDATE_SECOND_REVIEW_DENIED: &str = "CANDIDATE_SECOND_REVIEW_DENIED";

    // Admin bootstrap
    pub const ADMIN_SEED_USED: &str = "ADMIN_SEED_USED";
    pub const ADMIN_SEED_FAILED: &str = "ADMIN_SEED_FAILED";

    // Audit trail access itself
    pub const AUDIT_LOG_VIEWED: &str = "AUDIT_LOG_VIEWED";

    // Organization / unit administration (madde 12-13)
    pub const ORGANIZATION_CREATED: &str = "ORGANIZATION_CREATED";
    pub const ORGANIZATION_UNIT_CREATED: &str = "ORGANIZATION_UNIT_CREATED";
    pub const MEMBERSHIP_ASSIGNED: &str = "MEMBERSHIP_ASSIGNED";
    pub const MEMBERSHIP_REMOVED: &str = "MEMBERSHIP_REMOVED";

    pub const CANDIDATE_CREATED: &str = "CANDIDATE_CREATED";
    pub const CANDIDATE_REFERENCE_PHOTO_ENROLLED: &str = "CANDIDATE_REFERENCE_PHOTO_ENROLLED";
    pub const CANDIDATE_TEMPLATE_REVOKED: &str = "CANDIDATE_TEMPLATE_REVOKED";
    pub const CANDIDATE_EVIDENCE_COLLECTED: &str = "CANDIDATE_EVIDENCE_COLLECTED";
    pub const CANDIDATE_ENTITY_RELATION_ADDED: &str = "CANDIDATE_ENTITY_RELATION_ADDED";
}

pub mod result {
    pub const SUCCESS: &str = "success";
    pub const FAILURE: &str = "failure";
    pub const DENIED: &str = "denied";
}

/// Builder for a single audit event. Construct with `new`, chain in
/// whatever context is available at the call site, then `.save(state)`.
/// `save` never propagates a DB error to the caller — a broken audit
/// write must not take down the request that triggered it — it only
/// logs a warning so the gap is visible in structured logs.
pub struct AuditRecorder {
    action: &'static str,
    result: &'static str,
    request_id: String,
    actor_user_id: Option<String>,
    actor_user_code: Option<String>,
    actor_role: Option<String>,
    case_reference: Option<String>,
    resource_type: Option<&'static str>,
    resource_id: Option<String>,
    source: Option<&'static str>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    metadata: Option<serde_json::Value>,
}

impl AuditRecorder {
    pub fn new(action: &'static str, result: &'static str, request_id: impl Into<String>) -> Self {
        Self {
            action,
            result,
            request_id: request_id.into(),
            actor_user_id: None,
            actor_user_code: None,
            actor_role: None,
            case_reference: None,
            resource_type: None,
            resource_id: None,
            source: Some("api"),
            ip_address: None,
            user_agent: None,
            metadata: None,
        }
    }

    /// Records the authenticated caller from their access-token claims.
    pub fn actor(mut self, claims: &Claims) -> Self {
        self.actor_user_id = Some(claims.id.clone());
        self.actor_user_code = Some(claims.user_code.clone());
        self.actor_role = Some(claims.role.clone());
        self
    }

    /// Same as `actor`, but for call sites that only conditionally have
    /// claims on hand (e.g. re-decoding a bearer token that a prior
    /// authorization check already required to be present, but which
    /// isn't itself threaded through as a `Claims` value).
    pub fn actor_opt(self, claims: Option<&Claims>) -> Self {
        match claims {
            Some(claims) => self.actor(claims),
            None => self,
        }
    }

    /// Records an actor identified some other way (e.g. a user row looked
    /// up by user code before a login attempt is known to have succeeded).
    pub fn actor_by_id(
        mut self,
        user_id: impl Into<String>,
        user_code: impl Into<String>,
        role: impl Into<String>,
    ) -> Self {
        self.actor_user_id = Some(user_id.into());
        self.actor_user_code = Some(user_code.into());
        self.actor_role = Some(role.into());
        self
    }

    /// Extracts client IP (only when this deployment trusts its proxy —
    /// see `auth::client_ip`) and user agent from the request headers.
    pub fn headers(mut self, headers: &HeaderMap) -> Self {
        self.ip_address = crate::auth::client_ip(headers);
        self.user_agent = crate::auth::user_agent(headers);
        self
    }

    pub fn case_reference(mut self, value: impl Into<String>) -> Self {
        self.case_reference = Some(value.into());
        self
    }

    pub fn resource(mut self, resource_type: &'static str, resource_id: impl Into<String>) -> Self {
        self.resource_type = Some(resource_type);
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Structured, non-sensitive context specific to this action (e.g.
    /// `{"role": "OPERATOR"}` for a role change). Never pass raw
    /// passwords, tokens, national IDs, or biometric data here — see the
    /// module doc comment.
    pub fn metadata(mut self, value: serde_json::Value) -> Self {
        self.metadata = Some(value);
        self
    }

    fn to_new_event<'a>(&'a self, organization_id: Option<&'a str>) -> NewAuditEvent<'a> {
        NewAuditEvent {
            actor_user_id: self.actor_user_id.as_deref(),
            actor_user_code: self.actor_user_code.as_deref(),
            actor_role: self.actor_role.as_deref(),
            action: self.action,
            request_id: &self.request_id,
            case_reference: self.case_reference.as_deref(),
            resource_type: self.resource_type,
            resource_id: self.resource_id.as_deref(),
            result: self.result,
            source: self.source,
            ip_address: self.ip_address.as_deref(),
            user_agent: self.user_agent.as_deref(),
            metadata: self.metadata.as_ref().map(|v| v.to_string()),
            organization_id,
            organization_unit_id: None,
        }
    }

    /// Resolves the acting user's organization (madde 12-13) so the
    /// stored event can be scoped the same way the resource it concerns
    /// is. `None` for an event with no actor, or an actor with no
    /// membership — those events remain visible to every role that could
    /// see them before the org model existed (see
    /// `permission::can_view_scoped_resource`).
    async fn resolve_organization_id(&self, state: &AppState) -> Option<String> {
        let actor_user_id = self.actor_user_id.as_deref()?;
        crate::db::primary_organization_id(&state.backend, actor_user_id)
            .await
            .ok()
            .flatten()
    }

    /// Best-effort: logs a warning and returns normally on failure — used
    /// for events whose loss, while undesirable, must not itself take down
    /// the request that triggered them (e.g. a login attempt). See
    /// `save_mandatory` for the alternative used by security-critical
    /// actions (madde 17 — MANDATORY vs BEST_EFFORT).
    pub async fn save(self, state: &AppState) {
        let organization_id = self.resolve_organization_id(state).await;
        let event = self.to_new_event(organization_id.as_deref());
        if let Err(err) = insert_audit_event(&state.backend, event).await {
            tracing::warn!(action = self.action, error = %err, "failed to write audit event");
        }
    }

    /// For actions the instructions classify as MANDATORY (biometric
    /// search, candidate enrollment/revocation, verification decisions,
    /// role/permission changes, account ban/unban, MFA reset, sensitive
    /// export — see item 17 in `docs/HARDENING_CHECKLIST.md`): propagates
    /// a write failure instead of swallowing it, so the caller can refuse
    /// to report the triggering operation as successful. This does not
    /// roll back a database write the operation itself already committed
    /// (that would need the audit insert to share the same transaction, or
    /// a transactional outbox — see the module-level limitation noted in
    /// the checklist); it does guarantee the operation is never reported
    /// to the client as a clean success while its mandatory audit record
    /// silently failed to write.
    pub async fn save_mandatory(self, state: &AppState) -> Result<(), ApiError> {
        let action = self.action;
        let organization_id = self.resolve_organization_id(state).await;
        let event = self.to_new_event(organization_id.as_deref());
        insert_audit_event(&state.backend, event)
            .await
            .map_err(|err| {
                tracing::error!(action, error = %err, "mandatory audit event failed to write");
                ApiError::new(
                    "AUDIT_WRITE_FAILED",
                    "errors.auditWriteFailed",
                    String::new(),
                )
            })
    }
}

const DEFAULT_PAGE_SIZE: i64 = 50;
const MAX_PAGE_SIZE: i64 = 200;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuery {
    pub date_from: Option<String>,
    pub date_to: Option<String>,
    pub actor: Option<String>,
    pub action: Option<String>,
    pub case_reference: Option<String>,
    pub resource_type: Option<String>,
    pub result: Option<String>,
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

fn audit_event_json(row: &AuditEventRow) -> serde_json::Value {
    let metadata = row
        .metadata
        .as_deref()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok());
    serde_json::json!({
        "id": row.id,
        "timestamp": row.timestamp,
        "actorUserId": row.actor_user_id,
        "actorUserCode": row.actor_user_code,
        "actorRole": row.actor_role,
        "action": row.action,
        "requestId": row.request_id,
        "caseReference": row.case_reference,
        "resourceType": row.resource_type,
        "resourceId": row.resource_id,
        "result": row.result,
        "source": row.source,
        "ipAddress": row.ip_address,
        "userAgent": row.user_agent,
        "metadata": metadata,
        "organizationId": row.organization_id,
        "organizationUnitId": row.organization_unit_id,
        "sequence": row.sequence,
        "previousHash": row.previous_hash,
        "eventHash": row.event_hash,
    })
}

/// `GET /api/v1/audit/integrity` — recomputes the hash chain over every
/// audit event and reports whether it's intact (see
/// `db::audit::verify_chain`). Same access restriction as reading the
/// audit trail itself: the integrity guarantee is only meaningful if
/// checking it is also access-controlled.
pub async fn verify_audit_integrity_route(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    if !require_role(&state, &headers, permission::can_view_audit_log) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }
    match verify_chain(&state.backend).await {
        Ok(report) => Json(serde_json::json!({
            "eventsChecked": report.events_checked,
            "intact": report.intact,
            "breaks": report.breaks,
        }))
        .into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

/// `GET /api/v1/audit` — server-side paginated, filtered view over the
/// append-only audit trail. Restricted to `AUDITOR`, `SECURITY_ADMIN`, and
/// `SYSTEM_ADMIN` — the append-only guarantee is only meaningful if
/// reading it is also access-controlled.
pub async fn list_audit_events_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = crate::auth::auth_user_from_headers(&headers, &state.secrets.jwt_secret)
    else {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    };
    if !permission::can_view_audit_log(&claims.role) {
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }

    let date_from = query.date_from.as_deref().and_then(|v| v.parse().ok());
    let date_to = query.date_to.as_deref().and_then(|v| v.parse().ok());
    if (query.date_from.is_some() && date_from.is_none())
        || (query.date_to.is_some() && date_to.is_none())
    {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    // Object-level authorization (madde 12-13): holding a global audit
    // role (AUDITOR/SECURITY_ADMIN) does not by itself grant visibility
    // into every organization's events — only SYSTEM_ADMIN is exempt.
    let org_scope = if claims.role == crate::roles::SYSTEM_ADMIN {
        None
    } else {
        crate::db::user_organization_ids(&state.backend, &claims.id)
            .await
            .ok()
    };

    let filter = AuditEventFilter {
        date_from,
        date_to,
        actor_user_id: query.actor,
        action: query.action,
        case_reference: query.case_reference,
        resource_type: query.resource_type,
        result: query.result,
        org_scope,
    };
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);

    match list_audit_events(&state.backend, &filter, page, page_size).await {
        Ok((rows, total)) => Json(serde_json::json!({
            "items": rows.iter().map(audit_event_json).collect::<Vec<_>>(),
            "page": page,
            "pageSize": page_size,
            "total": total,
        }))
        .into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}
