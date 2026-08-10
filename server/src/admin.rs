use axum::extract::{Path, Query, State};
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
    count_active_system_admins, create_user, delete_user, list_users_page as load_users_page,
    load_user_by_id, revoke_all_sessions_for_user, soft_delete_user, update_user_flags,
    update_user_profile, AppState,
};
use crate::email::escape_html;
use crate::error::{request_id, ApiError};
use crate::permission;
use crate::roles;

#[derive(Debug, Deserialize)]
pub struct BanPayload {
    pub reason: Option<String>,
}

const DEFAULT_USER_PAGE_SIZE: i64 = 50;

#[derive(Debug, Deserialize)]
pub struct UserPageQuery {
    pub page: Option<i64>,
    #[serde(rename = "pageSize")]
    pub page_size: Option<i64>,
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

/// Masks all but the last two digits of a national ID for display — the
/// admin panel needs enough of the value to confirm it's the right
/// person's record, not the full number. Full digits are still stored
/// and used server-side (uniqueness check on registration); they are
/// simply never sent back to a client. See `docs/SECURITY_ARCHITECTURE.md`.
fn mask_national_id(value: &str) -> String {
    let len = value.chars().count();
    if len <= 2 {
        return "*".repeat(len);
    }
    let visible: String = value.chars().skip(len - 2).collect();
    format!("{}{}", "*".repeat(len - 2), visible)
}

fn user_json(user: &crate::db::UserRow, national_id_key: &[u8; 32]) -> serde_json::Value {
    let national_id = user
        .national_id_encrypted
        .as_deref()
        .and_then(|encrypted| crate::national_id::decrypt(national_id_key, encrypted))
        .map(|plaintext| mask_national_id(&plaintext));
    json!({
        "id": user.id,
        "userCode": user.user_code,
        "firstName": user.first_name,
        "lastName": user.last_name,
        "nationalId": national_id,
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

fn require_admin(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    if require_role(state, headers, permission::can_administer_users) {
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

pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<UserPageQuery>,
) -> Response {
    if let Some(denied) = require_admin(&state, &headers) {
        return denied;
    }
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(DEFAULT_USER_PAGE_SIZE);
    match load_users_page(&state.backend, page, page_size).await {
        Ok((rows, total)) => Json(json!({
            "items": rows.iter().map(|row| user_json(row, &state.secrets.national_id_encryption_key)).collect::<Vec<_>>(),
            "page": page,
            "pageSize": page_size.clamp(1, 200),
            "total": total,
        }))
        .into_response(),
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

    let (national_id_encrypted, national_id_lookup_hash) =
        crate::national_id::encrypt(&state.secrets.national_id_encryption_key, national_id);
    match create_user(
        &state.backend,
        &code,
        Some(&email),
        &first_name,
        &last_name,
        Some(&national_id_encrypted),
        Some(&national_id_lookup_hash),
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
            Json(json!({ "user": user_json(&user, &state.secrets.national_id_encryption_key) }))
                .into_response()
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

    let (national_id_encrypted, national_id_lookup_hash) =
        match payload.national_id.as_deref().map(str::trim) {
            Some(v) if !v.is_empty() => {
                if v.len() != 11 || !v.chars().all(|c| c.is_ascii_digit()) {
                    return ApiError::new("VALIDATION_ERROR", "errors.validation", rid)
                        .into_response();
                }
                let (encrypted, hash) =
                    crate::national_id::encrypt(&state.secrets.national_id_encryption_key, v);
                (Some(encrypted), Some(hash))
            }
            // Untouched — keep whatever is already stored rather than
            // re-encrypting (a fresh nonce each save is harmless, but
            // pointless work; carrying the existing value over is simplest).
            _ => (
                current.national_id_encrypted.clone(),
                current.national_id_lookup_hash.clone(),
            ),
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
        national_id_encrypted.as_deref(),
        national_id_lookup_hash.as_deref(),
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
            Json(json!({ "user": user_json(&user, &state.secrets.national_id_encryption_key) }))
                .into_response()
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

/// Refuses to ban/delete a `SYSTEM_ADMIN` account when it is the only
/// active one left — otherwise the platform could lock itself out of its
/// own administration with no way back short of re-running the
/// `seed-admin` bootstrap (which itself requires a still-set
/// `ADMIN_SEED_TOKEN`).
async fn would_remove_last_admin(state: &AppState, target: &crate::db::UserRow) -> bool {
    if target.role != roles::SYSTEM_ADMIN || target.is_banned {
        return false;
    }
    count_active_system_admins(&state.backend)
        .await
        .map(|count| count <= 1)
        .unwrap_or(false)
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
    if let Some(target) = load_user_by_id(&state.backend, &id).await.ok().flatten() {
        if would_remove_last_admin(&state, &target).await {
            return ApiError::new("LAST_ADMIN_PROTECTED", "errors.lastAdminProtected", rid)
                .into_response();
        }
    }
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

/// `POST /api/v1/admin/users/:id/mfa-reset` — removes a target account's
/// MFA credential and recovery codes entirely, forcing re-enrollment on
/// its next login. For an account whose role requires MFA
/// (`MFA_REQUIRED_ROLES`), this is the recovery path when a device/secret
/// is lost — the account cannot re-enroll itself without first logging
/// in, and it cannot log in without MFA, so an administrator must clear
/// the credential first.
pub async fn mfa_reset_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Some(denied) = require_admin(&state, &headers) {
        return denied;
    }
    let rid = request_id(&headers);
    let Some(target) = load_user_by_id(&state.backend, &id).await.ok().flatten() else {
        return ApiError::new("NOT_FOUND", "errors.notFound", rid).into_response();
    };
    if crate::mfa::admin_reset(&state, &target.id).await.is_err() {
        return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response();
    }
    AuditRecorder::new(action::MFA_RESET_BY_ADMIN, audit_result::SUCCESS, rid)
        .actor_opt(actor_claims(&state, &headers).as_ref())
        .headers(&headers)
        .resource("user", &target.id)
        .save(&state)
        .await;
    Json(json!({ "messageKey": "admin.mfaResetComplete" })).into_response()
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
    if let Some(target) = load_user_by_id(&state.backend, &id).await.ok().flatten() {
        if would_remove_last_admin(&state, &target).await {
            return ApiError::new("LAST_ADMIN_PROTECTED", "errors.lastAdminProtected", rid)
                .into_response();
        }
    }
    match soft_delete_user(&state.backend, &id).await {
        Ok(true) => {
            // A deleted account must stop working immediately, not just
            // for future logins — same reasoning as ban_user.
            let _ = revoke_all_sessions_for_user(&state.backend, &id).await;
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
///
/// Self-disables once at least one active `SYSTEM_ADMIN` exists: an
/// attacker who somehow learns `ADMIN_SEED_TOKEN` after the platform is
/// already running should not be able to mint themselves a fresh admin
/// account under a different `ADMIN_USER_CODE`. Set
/// `BOOTSTRAP_ENABLED=true` to explicitly re-open it for a deliberate
/// recovery (e.g. every admin account was lost).
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

    let bootstrap_explicitly_enabled = std::env::var("BOOTSTRAP_ENABLED").as_deref() == Ok("true");
    if !bootstrap_explicitly_enabled
        && count_active_system_admins(&state.backend)
            .await
            .unwrap_or(0)
            > 0
    {
        AuditRecorder::new(action::ADMIN_SEED_FAILED, audit_result::DENIED, rid.clone())
            .headers(&headers)
            .metadata(json!({ "reason": "already_bootstrapped" }))
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

    #[test]
    fn national_id_masking_keeps_only_the_last_two_digits() {
        assert_eq!(mask_national_id("12345678912"), "*********12");
    }

    #[test]
    fn national_id_masking_handles_short_values() {
        assert_eq!(mask_national_id("1"), "*");
        assert_eq!(mask_national_id(""), "");
        assert_eq!(mask_national_id("12"), "**");
    }
}
