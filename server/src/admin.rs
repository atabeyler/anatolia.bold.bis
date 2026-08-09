use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bcrypt::hash;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

use crate::audit::{action, result as audit_result, AuditRecorder};
use crate::auth::{
    auth_user_from_headers, consume_approval_token, peek_approval_token, public_user, require_role,
    Claims,
};
use crate::db::{
    create_user, delete_user, list_users as load_users, load_user_by_id,
    revoke_all_sessions_for_user, update_user_flags, update_user_profile, AppState,
};
use crate::email::escape_html;
use crate::error::ApiError;
use crate::roles;

#[derive(Debug, Deserialize)]
pub struct BanPayload {
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserPayload {
    pub user_code: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub national_id: String,
    pub email: String,
    pub is_admin: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserPayload {
    pub nickname: Option<String>,
    pub national_id: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
}

fn user_json(user: &crate::db::UserRow) -> serde_json::Value {
    json!({
        "id": user.id,
        "userCode": user.user_code,
        "firstName": user.first_name,
        "lastName": user.last_name,
        "nationalId": user.national_id,
        "email": user.email,
        "role": user.role,
        "isApproved": user.is_approved,
        "isBanned": user.is_banned,
        "banReason": user.ban_reason,
    })
}

/// Plain `!=` on the seed token would let a network attacker recover it
/// byte-by-byte from response-timing differences. Only ever called once,
/// at bootstrap, but the fix costs nothing.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |diff, (x, y)| diff | (x ^ y))
        == 0
}

const ADMIN_ROLES: &[&str] = &[roles::SYSTEM_ADMIN, roles::SECURITY_ADMIN];

fn require_admin(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if require_role(state, headers, ADMIN_ROLES) {
        None
    } else {
        Some(ApiError::new("FORBIDDEN", "errors.forbidden", request_id(headers)).into_response())
    }
}

/// The acting admin's claims, for attributing an audit event to a
/// specific actor. `require_admin` has already established that some
/// valid admin bearer token is present by the time any caller reaches
/// this — this just re-decodes it to get the identity to attribute to.
fn actor_claims(state: &AppState, headers: &HeaderMap) -> Option<Claims> {
    auth_user_from_headers(headers, &state.secrets.jwt_secret)
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

pub async fn list_users(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(denied) = require_admin(&state, &headers) {
        return denied;
    }
    match load_users(&state.backend).await {
        Ok(rows) => {
            let payload: Vec<_> = rows.iter().map(user_json).collect();
            Json(payload).into_response()
        }
        Err(_) => {
            ApiError::new("INTERNAL_ERROR", "errors.internal", request_id(&headers)).into_response()
        }
    }
}

/// Lets an admin create an account directly (immediately approved, no
/// self-registration/approval round trip) — for operators the admin sets
/// up in person rather than ones who self-register. Distinct from
/// `register`: no national ID is collected here, email is optional, and
/// the password policy is only a minimum length since the admin is
/// choosing it, not the account's eventual owner.
pub async fn create_user_route(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateUserPayload>,
) -> Response {
    if let Some(denied) = require_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);

    let code = payload.user_code.trim().to_uppercase();
    if !(4..=20).contains(&code.len())
        || !code
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }
    if payload.password.len() < 8 {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }
    let national_id = payload.national_id.trim();
    if national_id.len() != 11 || !national_id.chars().all(|c| c.is_ascii_digit()) {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }
    let email = payload.email.trim().to_lowercase();
    if email.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let first_name = payload
        .first_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&code)
        .to_string();
    let last_name = payload
        .last_name
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();

    let hashed = match hash(&payload.password, bcrypt::DEFAULT_COST) {
        Ok(v) => v,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    let role = if payload.is_admin {
        roles::SYSTEM_ADMIN
    } else {
        roles::DEFAULT_APPROVED_ROLE
    };

    match create_user(
        &state.backend,
        &code,
        Some(&email),
        &first_name,
        &last_name,
        Some(national_id),
        &hashed,
        role,
        true,
    )
    .await
    {
        Ok(Some(user)) => {
            AuditRecorder::new(action::USER_CREATED, audit_result::SUCCESS, rid.clone())
                .actor_opt(actor_claims(&state, &headers).as_ref())
                .headers(&headers)
                .resource("user", &user.id)
                .save(&state)
                .await;
            Json(json!({ "user": user_json(&user) })).into_response()
        }
        Ok(None) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
        Err(err) if err.to_string().to_lowercase().contains("unique") => {
            ApiError::new("CONFLICT", "errors.registrationConflict", rid).into_response()
        }
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

/// Admin edit of an existing account's nickname/national ID/email, and
/// optionally a password reset — this is the "Düzenle" action next to
/// ban/delete in the management panel, and also how an admin fulfils a
/// forgot-password request (see `auth::forgot_password`, which only
/// notifies the admin — it does not reset anything itself).
pub async fn update_user_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<UpdateUserPayload>,
) -> Response {
    if let Some(denied) = require_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);

    let Some(current) = load_user_by_id(&state.backend, &id).await.ok().flatten() else {
        return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response();
    };

    let first_name = payload
        .nickname
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&current.first_name)
        .to_string();

    let national_id = match payload.national_id.as_deref().map(str::trim) {
        Some(v) if !v.is_empty() => {
            if v.len() != 11 || !v.chars().all(|c| c.is_ascii_digit()) {
                return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
            }
            Some(v.to_string())
        }
        _ => current.national_id.clone(),
    };

    let email = match payload.email.as_deref().map(str::trim) {
        Some(v) if !v.is_empty() => Some(v.to_lowercase()),
        _ => current.email.clone(),
    };

    let password_hash = match payload.password.as_deref() {
        Some(p) if !p.is_empty() => {
            if p.len() < 8 {
                return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
            }
            match hash(p, bcrypt::DEFAULT_COST) {
                Ok(v) => v,
                Err(_) => {
                    return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response()
                }
            }
        }
        _ => current.password_hash.clone(),
    };

    match update_user_profile(
        &state.backend,
        &id,
        &first_name,
        email.as_deref(),
        national_id.as_deref(),
        &password_hash,
    )
    .await
    {
        Ok(Some(user)) => {
            AuditRecorder::new(action::USER_UPDATED, audit_result::SUCCESS, rid.clone())
                .actor_opt(actor_claims(&state, &headers).as_ref())
                .headers(&headers)
                .resource("user", &user.id)
                .save(&state)
                .await;
            Json(json!({ "user": user_json(&user) })).into_response()
        }
        Ok(None) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(err) if err.to_string().to_lowercase().contains("unique") => {
            ApiError::new("CONFLICT", "errors.registrationConflict", rid).into_response()
        }
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn approve_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(denied) = require_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    match update_user_flags(
        &state.backend,
        &id,
        Some(true),
        Some(false),
        None,
        Some(roles::DEFAULT_APPROVED_ROLE),
    )
    .await
    {
        Ok(Some(user)) => {
            if let Some(email) = user.email.as_deref() {
                crate::email::send_approval_email(
                    &user.first_name,
                    &user.last_name,
                    email,
                    &user.user_code,
                )
                .await;
            }
            AuditRecorder::new(action::REGISTRATION_APPROVED, audit_result::SUCCESS, rid)
                .actor_opt(actor_claims(&state, &headers).as_ref())
                .headers(&headers)
                .resource("user", &user.id)
                .save(&state)
                .await;
            Json(json!({ "user": public_user(&user) })).into_response()
        }
        Ok(None) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn reject_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(denied) = require_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    let user = load_user_by_id(&state.backend, &id).await.ok().flatten();
    let actor = actor_claims(&state, &headers);
    match delete_user(&state.backend, &id).await {
        Ok(true) => {
            if let Some(user) = &user {
                if let Some(email) = user.email.as_deref() {
                    crate::email::send_rejection_email(&user.first_name, &user.last_name, email)
                        .await;
                }
            }
            AuditRecorder::new(action::REGISTRATION_REJECTED, audit_result::SUCCESS, rid)
                .actor_opt(actor.as_ref())
                .headers(&headers)
                .resource("user", &id)
                .save(&state)
                .await;
            Json(json!({ "messageKey": "admin.requestRejected" })).into_response()
        }
        Ok(false) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn ban_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<BanPayload>,
) -> Response {
    if let Some(denied) = require_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    match update_user_flags(
        &state.backend,
        &id,
        None,
        Some(true),
        payload.reason.as_deref(),
        None,
    )
    .await
    {
        Ok(Some(_)) => {
            // A ban must take effect immediately, not just for future
            // logins — a short-lived access token issued before the ban
            // would otherwise keep working until it expires.
            let _ = revoke_all_sessions_for_user(&state.backend, &id).await;
            AuditRecorder::new(action::USER_BANNED, audit_result::SUCCESS, rid)
                .actor_opt(actor_claims(&state, &headers).as_ref())
                .headers(&headers)
                .resource("user", &id)
                .metadata(json!({ "reason": payload.reason }))
                .save(&state)
                .await;
            Json(json!({ "messageKey": "admin.userBanned" })).into_response()
        }
        Ok(None) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn unban_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(denied) = require_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    match update_user_flags(&state.backend, &id, None, Some(false), None, None).await {
        Ok(Some(_)) => {
            AuditRecorder::new(action::USER_UNBANNED, audit_result::SUCCESS, rid)
                .actor_opt(actor_claims(&state, &headers).as_ref())
                .headers(&headers)
                .resource("user", &id)
                .save(&state)
                .await;
            Json(json!({ "messageKey": "admin.banLifted" })).into_response()
        }
        Ok(None) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

pub async fn delete_user_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(denied) = require_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    match delete_user(&state.backend, &id).await {
        Ok(true) => {
            AuditRecorder::new(action::USER_DELETED, audit_result::SUCCESS, rid)
                .actor_opt(actor_claims(&state, &headers).as_ref())
                .headers(&headers)
                .resource("user", &id)
                .save(&state)
                .await;
            Json(json!({ "messageKey": "admin.userDeleted" })).into_response()
        }
        Ok(false) => ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response(),
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

/// One-time bootstrap: creates the first SYSTEM_ADMIN account. Requires
/// `ADMIN_SEED_TOKEN`, `ADMIN_USER_CODE`, `ADMIN_PASSWORD`, `ADMIN_EMAIL`
/// to all be set — see docs/ENVIRONMENT.md. Without a seeded admin,
/// nothing in the application can be administered.
pub async fn seed_admin(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rid = request_id(&headers);
    if !state
        .rate_limiter
        .check("seed-admin", 5, Duration::from_secs(15 * 60))
    {
        return ApiError::new("RATE_LIMITED", "errors.rateLimited", rid).into_response();
    }
    let expected = std::env::var("ADMIN_SEED_TOKEN").unwrap_or_default();
    let provided = headers
        .get("x-seed-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if expected.is_empty() || !constant_time_eq(provided, &expected) {
        AuditRecorder::new(action::ADMIN_SEED_FAILED, audit_result::DENIED, rid.clone())
            .headers(&headers)
            .save(&state)
            .await;
        return ApiError::new("FORBIDDEN", "errors.forbidden", rid).into_response();
    }

    let (Ok(code), Ok(password), Ok(email)) = (
        std::env::var("ADMIN_USER_CODE"),
        std::env::var("ADMIN_PASSWORD"),
        std::env::var("ADMIN_EMAIL"),
    ) else {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    };
    if code.trim().is_empty() || password.is_empty() || email.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let hashed = match hash(password, bcrypt::DEFAULT_COST) {
        Ok(v) => v,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    match create_user(
        &state.backend,
        &code.trim().to_uppercase(),
        Some(&email),
        "System",
        "Administrator",
        None,
        &hashed,
        roles::SYSTEM_ADMIN,
        true,
    )
    .await
    {
        Ok(Some(user)) => {
            AuditRecorder::new(action::ADMIN_SEED_USED, audit_result::SUCCESS, rid)
                .headers(&headers)
                .resource("user", &user.id)
                .save(&state)
                .await;
            Json(json!({ "messageKey": "admin.adminCreated" })).into_response()
        }
        Ok(None) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
        // Re-running seed-admin with the same ADMIN_USER_CODE/ADMIN_EMAIL is
        // the expected way to check "has this already been bootstrapped" —
        // a unique-constraint violation here means yes, not a real failure.
        Err(err) if err.to_string().to_lowercase().contains("unique") => {
            Json(json!({ "messageKey": "admin.alreadySeeded" })).into_response()
        }
        Err(_) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    }
}

fn html_page(title: &str, body: &str) -> Response {
    let page = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{background:#0b0e14;color:#e4e7ee;font-family:system-ui,sans-serif;padding:48px;max-width:520px;margin:0 auto}}
h1{{color:#3b82f6;font-size:16px;letter-spacing:.1em}}
.btn{{display:inline-block;padding:12px 28px;margin:8px 8px 0 0;text-decoration:none;font-size:13px;border:1px solid rgba(59,130,246,0.6);cursor:pointer;font-family:inherit}}
form{{display:inline}}
.approve{{background:rgba(34,197,94,0.15);color:#22c55e;border-color:rgba(34,197,94,0.6)}}
.reject{{background:rgba(239,68,68,0.15);color:#ef4444;border-color:rgba(239,68,68,0.6)}}</style>
</head><body><h1>{title}</h1>{body}</body></html>"#
    );
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        page,
    )
        .into_response()
}

pub async fn review(State(state): State<AppState>, Path(token): Path<String>) -> Response {
    let Some(user_id) = peek_approval_token(&state, &token).await else {
        return html_page(
            "Invalid or expired link",
            "<p>This approval link is invalid, has expired, or has already been used.</p>",
        );
    };
    let Some(user) = load_user_by_id(&state.backend, &user_id)
        .await
        .ok()
        .flatten()
    else {
        return html_page(
            "Not found",
            "<p>This registration request no longer exists.</p>",
        );
    };
    if user.is_approved {
        return html_page(
            "Already approved",
            &format!(
                "<p>{} {} has already been approved.</p>",
                escape_html(&user.first_name),
                escape_html(&user.last_name)
            ),
        );
    }
    let body = format!(
        r#"<table style="width:100%;margin:20px 0;font-size:14px">
        <tr><td style="color:#8b93a7;padding:6px 0;width:140px">Full name</td><td>{} {}</td></tr>
        <tr><td style="color:#8b93a7;padding:6px 0">Email</td><td>{}</td></tr>
        <tr><td style="color:#8b93a7;padding:6px 0">User code</td><td>{}</td></tr>
        </table>
        <form method="post" action="/api/v1/admin/quick-approve/{token}"><button type="submit" class="btn approve">Approve</button></form>
        <form method="post" action="/api/v1/admin/quick-reject/{token}"><button type="submit" class="btn reject">Reject</button></form>"#,
        escape_html(&user.first_name),
        escape_html(&user.last_name),
        escape_html(user.email.as_deref().unwrap_or("-")),
        escape_html(&user.user_code),
    );
    html_page("Review registration request", &body)
}

pub async fn quick_approve(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    let Some(user_id) = consume_approval_token(&state, &token, "approved").await else {
        return html_page(
            "Invalid or expired link",
            "<p>This approval link is invalid, has expired, or has already been used.</p>",
        );
    };
    match update_user_flags(
        &state.backend,
        &user_id,
        Some(true),
        Some(false),
        None,
        Some(roles::DEFAULT_APPROVED_ROLE),
    )
    .await
    {
        Ok(Some(user)) => {
            if let Some(email) = user.email.as_deref() {
                crate::email::send_approval_email(
                    &user.first_name,
                    &user.last_name,
                    email,
                    &user.user_code,
                )
                .await;
            }
            AuditRecorder::new(action::REGISTRATION_APPROVED, audit_result::SUCCESS, rid)
                .headers(&headers)
                .resource("user", &user.id)
                .metadata(json!({ "source": "email_link" }))
                .save(&state)
                .await;
            html_page(
                "Approved",
                &format!(
                    "<p>{} {} has been approved and notified by email.</p>",
                    escape_html(&user.first_name),
                    escape_html(&user.last_name)
                ),
            )
        }
        Ok(None) => html_page(
            "Not found",
            "<p>This registration request no longer exists.</p>",
        ),
        Err(err) => html_page("Error", &format!("<p>{err}</p>")),
    }
}

pub async fn quick_reject(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Response {
    let rid = request_id(&headers);
    let Some(user_id) = consume_approval_token(&state, &token, "rejected").await else {
        return html_page(
            "Invalid or expired link",
            "<p>This approval link is invalid, has expired, or has already been used.</p>",
        );
    };
    let user = load_user_by_id(&state.backend, &user_id)
        .await
        .ok()
        .flatten();
    match delete_user(&state.backend, &user_id).await {
        Ok(true) => {
            AuditRecorder::new(action::REGISTRATION_REJECTED, audit_result::SUCCESS, rid)
                .headers(&headers)
                .resource("user", &user_id)
                .metadata(json!({ "source": "email_link" }))
                .save(&state)
                .await;
            if let Some(user) = user {
                if let Some(email) = user.email.as_deref() {
                    crate::email::send_rejection_email(&user.first_name, &user.last_name, email)
                        .await;
                }
                html_page(
                    "Rejected",
                    &format!(
                        "<p>{} {} has been rejected and notified by email.</p>",
                        escape_html(&user.first_name),
                        escape_html(&user.last_name)
                    ),
                )
            } else {
                html_page("Rejected", "<p>Registration request rejected.</p>")
            }
        }
        Ok(false) => html_page(
            "Not found",
            "<p>This registration request no longer exists.</p>",
        ),
        Err(err) => html_page("Error", &format!("<p>{err}</p>")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_strings_are_equal() {
        assert!(constant_time_eq("seed-token-123", "seed-token-123"));
    }

    #[test]
    fn different_content_same_length_is_not_equal() {
        assert!(!constant_time_eq("seed-token-123", "seed-token-124"));
    }

    #[test]
    fn different_length_is_not_equal() {
        assert!(!constant_time_eq("short", "much-longer-value"));
    }
}
