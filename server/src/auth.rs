use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::audit::{action, result as audit_result, AuditRecorder};
use crate::db::{
    consume_approval_token as consume_single_use_token,
    create_approval_token as create_single_use_token, create_session, create_user,
    find_approval_token_by_hash as find_single_use_token_by_hash, find_session_by_family,
    load_registration_tracking_status, load_user_by_code, load_user_by_email, load_user_by_id,
    revoke_all_sessions_for_user, revoke_session, revoke_session_family, rotate_session,
    set_registration_tracking_token, update_user_password, AppState, UserRow,
};
use crate::error::{request_id, ApiError};
use crate::roles;

const PASSWORD_RESET_PURPOSE: &str = "password_reset";
const PASSWORD_RESET_TOKEN_TTL_HOURS: i64 = 1;

const ACCESS_TOKEN_TTL_SECS: i64 = 15 * 60;
const REFRESH_TOKEN_TTL_DAYS: i64 = 30;
const REGISTRATION_TRACKING_TOKEN_TTL_DAYS: i64 = 14;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub id: String,
    pub user_code: String,
    pub email: String,
    pub role: String,
    pub exp: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RefreshClaims {
    sub: String,
    family: String,
    jti: String,
    exp: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPayload {
    pub first_name: String,
    pub last_name: String,
    pub national_id: String,
    pub email: String,
    pub password: String,
    pub user_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginPayload {
    pub user_code: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgotPasswordPayload {
    pub identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicUser {
    pub id: String,
    pub user_code: String,
    pub email: Option<String>,
    pub role: String,
    pub first_name: String,
    pub last_name: String,
}

pub fn public_user(user: &UserRow) -> PublicUser {
    PublicUser {
        id: user.id.clone(),
        user_code: user.user_code.clone(),
        email: user.email.clone(),
        role: user.role.clone(),
        first_name: user.first_name.clone(),
        last_name: user.last_name.clone(),
    }
}

pub fn validate_password(password: &str) -> Option<&'static str> {
    if password.len() < 8 {
        return Some("Password must be at least 8 characters.");
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Some("Password must contain at least one uppercase letter.");
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Some("Password must contain at least one lowercase letter.");
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Some("Password must contain at least one digit.");
    }
    if !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        return Some("Password must contain at least one punctuation/special character.");
    }
    None
}

fn sign_access(user: &UserRow, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        id: user.id.clone(),
        user_code: user.user_code.clone(),
        email: user.email.clone().unwrap_or_default(),
        role: user.role.clone(),
        exp: (Utc::now().timestamp() + ACCESS_TOKEN_TTL_SECS) as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// Random hex string of `bytes` bytes of entropy — used for both the
/// refresh JWT's `jti` (so two refresh tokens signed in the same instant
/// still hash differently) and the registration tracking token.
fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn sign_refresh(
    user_id: &str,
    family: &str,
    secret: &str,
    expires_at: DateTime<Utc>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = RefreshClaims {
        sub: user_id.to_string(),
        family: family.to_string(),
        jti: random_hex(16),
        exp: expires_at.timestamp() as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

/// True only when the request's `Origin` genuinely names a different host
/// than the one it was sent to. A same-origin browser tab hitting its own
/// `/api/v1/auth/login` still sends an `Origin` header, but it matches
/// `Host`, so this returns false for the overwhelming majority of traffic.
fn is_cross_origin_request(headers: &HeaderMap) -> bool {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let origin_host = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(|o| o.split("://").nth(1));
    matches!((host, origin_host), (Some(host), Some(origin_host)) if origin_host != host)
}

fn is_production() -> bool {
    crate::config::is_production()
}

fn cookie_value(token: &str, headers: &HeaderMap) -> String {
    let same_site = if !is_production() {
        "Strict"
    } else if is_cross_origin_request(headers) {
        "None"
    } else {
        "Lax"
    };
    format!(
        "refresh_token={}; Path=/; HttpOnly; SameSite={}; Max-Age={};{}",
        token,
        same_site,
        REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60,
        if is_production() { " Secure;" } else { "" },
    )
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').map(|part| part.trim()).find_map(|part| {
        part.strip_prefix(&format!("{name}="))
            .map(|v| v.to_string())
    })
}

/// Only trusts `X-Forwarded-For` when this deployment is known to sit
/// behind a trusted reverse proxy (Render always fronts the app with one
/// in production; `TRUST_PROXY=true` opts a local reverse-proxy setup in
/// too). Otherwise the header is attacker-controlled and ignored — better
/// no IP than a spoofed one silently driving rate limits or audit trails.
fn trust_proxy() -> bool {
    std::env::var("TRUST_PROXY")
        .map(|v| v == "true")
        .unwrap_or_else(|_| is_production())
}

pub(crate) fn client_ip(headers: &HeaderMap) -> Option<String> {
    if !trust_proxy() {
        return None;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub(crate) fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(300).collect())
}

pub fn decode_access_token(token: &str, secret: &str) -> Option<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .ok()
    .map(|data| data.claims)
}

fn decode_refresh_token(token: &str, secret: &str) -> Option<RefreshClaims> {
    decode::<RefreshClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .ok()
    .map(|data| data.claims)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ApprovalClaims {
    user_id: String,
    purpose: String,
    jti: String,
    exp: usize,
}

const APPROVAL_TOKEN_TTL_DAYS: i64 = 3;
const APPROVAL_PURPOSE: &str = "registration_approval";

/// Signs a link a pending registration can be approved/rejected through
/// directly from the admin's email, without needing to be logged in —
/// possession of this token (mailed only to `ADMIN_EMAIL`) is the
/// authorization. Uses its own secret (`APPROVAL_TOKEN_SECRET`, distinct
/// from both the access and refresh secrets) and is additionally recorded
/// server-side in `approval_tokens` (as a hash, keyed by `jti`) so it can
/// be marked consumed and rejected on reuse even though the JWT itself
/// would still verify.
pub async fn sign_approval_token(state: &AppState, user_id: &str) -> Result<String, ApiError> {
    let expires_at = Utc::now() + ChronoDuration::days(APPROVAL_TOKEN_TTL_DAYS);
    let claims = ApprovalClaims {
        user_id: user_id.to_string(),
        purpose: APPROVAL_PURPOSE.to_string(),
        jti: random_hex(16),
        exp: expires_at.timestamp() as usize,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.secrets.approval_token_secret.as_bytes()),
    )
    .map_err(|_| ApiError::new("INTERNAL_ERROR", "errors.internal", String::new()))?;
    crate::db::create_approval_token(
        &state.backend,
        user_id,
        &sha256_hex(&token),
        APPROVAL_PURPOSE,
        expires_at,
    )
    .await
    .map_err(|_| ApiError::new("INTERNAL_ERROR", "errors.internal", String::new()))?;
    Ok(token)
}

/// Verifies an approval-link token cryptographically *and* against its
/// single-use server-side record; on success, atomically marks it
/// consumed with `result` (`"approved"`/`"rejected"`) so the same link can
/// never apply twice. Returns the target user's id only when both checks
/// pass.
pub async fn consume_approval_token(state: &AppState, token: &str, result: &str) -> Option<String> {
    let claims = decode::<ApprovalClaims>(
        token,
        &DecodingKey::from_secret(state.secrets.approval_token_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .ok()?
    .claims;
    if claims.purpose != APPROVAL_PURPOSE {
        return None;
    }
    let row = crate::db::find_approval_token_by_hash(&state.backend, &sha256_hex(token))
        .await
        .ok()??;
    if row.user_id != claims.user_id {
        return None;
    }
    let expires_at: DateTime<Utc> = row.expires_at.parse().ok()?;
    if expires_at < Utc::now() || row.consumed_at.is_some() {
        return None;
    }
    let consumed = crate::db::consume_approval_token(&state.backend, &row.id, result)
        .await
        .ok()?;
    if !consumed {
        return None;
    }
    Some(claims.user_id)
}

/// Read-only counterpart to `consume_approval_token`, for the GET review
/// page that only displays the pending request — approving/rejecting
/// happens through a separate POST that does consume the token.
pub async fn peek_approval_token(state: &AppState, token: &str) -> Option<String> {
    let claims = decode::<ApprovalClaims>(
        token,
        &DecodingKey::from_secret(state.secrets.approval_token_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .ok()?
    .claims;
    if claims.purpose != APPROVAL_PURPOSE {
        return None;
    }
    let row = crate::db::find_approval_token_by_hash(&state.backend, &sha256_hex(token))
        .await
        .ok()??;
    if row.user_id != claims.user_id || row.consumed_at.is_some() {
        return None;
    }
    let expires_at: DateTime<Utc> = row.expires_at.parse().ok()?;
    if expires_at < Utc::now() {
        return None;
    }
    Some(claims.user_id)
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(|s| s.to_string())
}

pub fn auth_user_from_headers(headers: &HeaderMap, secret: &str) -> Option<Claims> {
    decode_access_token(&bearer_token(headers)?, secret)
}

/// `allowed` is one of the named policy functions in `crate::permission`
/// (e.g. `permission::can_view_audit_log`) rather than an inline role list,
/// so the set of roles permitted to perform an action is defined in exactly
/// one place.
pub fn require_role(state: &AppState, headers: &HeaderMap, allowed: fn(&str) -> bool) -> bool {
    auth_user_from_headers(headers, &state.secrets.jwt_secret)
        .map(|claims| allowed(claims.role.as_str()))
        .unwrap_or(false)
}

fn unauthorized(headers: &HeaderMap) -> Response {
    ApiError::new("UNAUTHORIZED", "errors.unauthorized", request_id(headers)).into_response()
}

pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return unauthorized(&headers);
    };
    match load_user_by_id(&state.backend, &claims.id).await {
        Ok(Some(user)) => Json(public_user(&user)).into_response(),
        _ => unauthorized(&headers),
    }
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RegisterPayload>,
) -> Response {
    let rid = request_id(&headers);

    // Keyed globally (not per-key): an attacker controls every field in
    // this payload, so a per-key limit is trivially bypassed by varying
    // user_code/email each time. Every registration also fires an admin
    // notification email, so unthrottled spam floods the admin's inbox.
    if !state
        .rate_limiter
        .check("register", 20, Duration::from_secs(15 * 60))
    {
        return ApiError::new("RATE_LIMITED", "errors.rateLimited", rid).into_response();
    }

    if payload.first_name.trim().is_empty()
        || payload.last_name.trim().is_empty()
        || payload.email.trim().is_empty()
        || payload.password.is_empty()
        || payload.user_code.trim().is_empty()
        || payload.national_id.trim().is_empty()
    {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let national_id = payload.national_id.trim();
    if national_id.len() != 11 || !national_id.chars().all(|c| c.is_ascii_digit()) {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let code = payload.user_code.trim().to_uppercase();
    if !(4..=20).contains(&code.len())
        || !code
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    if validate_password(&payload.password).is_some() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let hashed = match hash(&payload.password, DEFAULT_COST) {
        Ok(v) => v,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };

    let email = payload.email.trim().to_lowercase();
    match create_user(
        &state.backend,
        &code,
        Some(&email),
        payload.first_name.trim(),
        payload.last_name.trim(),
        Some(national_id),
        &hashed,
        roles::PENDING,
        false,
    )
    .await
    {
        Ok(Some(user)) => {
            // Unguessable pointer the frontend polls with instead of the
            // (guessable) user code — see registration_status.
            let tracking_token = random_hex(32);
            let tracking_expires_at =
                Utc::now() + ChronoDuration::days(REGISTRATION_TRACKING_TOKEN_TTL_DAYS);
            let _ = set_registration_tracking_token(
                &state.backend,
                &user.id,
                &tracking_token,
                tracking_expires_at,
            )
            .await;

            if let Ok(token) = sign_approval_token(&state, &user.id).await {
                crate::email::send_admin_registration_notification(
                    crate::email::RegistrationInfo {
                        first_name: &user.first_name,
                        last_name: &user.last_name,
                        email: user.email.as_deref().unwrap_or_default(),
                        user_code: &user.user_code,
                        approval_token: &token,
                    },
                )
                .await;
            }

            AuditRecorder::new(
                action::REGISTRATION_CREATED,
                audit_result::SUCCESS,
                rid.clone(),
            )
            .actor_by_id(&user.id, &user.user_code, roles::PENDING)
            .headers(&headers)
            .save(&state)
            .await;

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "messageKey": "auth.registrationPending",
                    "registrationTrackingToken": tracking_token,
                })),
            )
                .into_response()
        }
        Ok(None) => ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
        Err(err) => {
            if err.to_string().to_lowercase().contains("unique") {
                ApiError::new("CONFLICT", "errors.registrationConflict", rid).into_response()
            } else {
                ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response()
            }
        }
    }
}

/// Issues an access token plus a brand-new session (family id, hashed
/// refresh token stored server-side, raw refresh token only ever placed
/// in the HttpOnly cookie).
async fn issue_session(
    state: &AppState,
    user: &UserRow,
    headers: &HeaderMap,
) -> Result<(String, String), ApiError> {
    let family = uuid::Uuid::new_v4().to_string();
    let expires_at = Utc::now() + ChronoDuration::days(REFRESH_TOKEN_TTL_DAYS);
    let refresh_token = sign_refresh(
        &user.id,
        &family,
        &state.secrets.jwt_refresh_secret,
        expires_at,
    )
    .map_err(|_| ApiError::new("INTERNAL_ERROR", "errors.internal", String::new()))?;
    create_session(
        &state.backend,
        &user.id,
        &sha256_hex(&refresh_token),
        &family,
        expires_at,
        user_agent(headers).as_deref(),
        client_ip(headers).as_deref(),
        "login",
    )
    .await
    .map_err(|_| ApiError::new("INTERNAL_ERROR", "errors.internal", String::new()))?;
    let access_token = sign_access(user, &state.secrets.jwt_secret)
        .map_err(|_| ApiError::new("INTERNAL_ERROR", "errors.internal", String::new()))?;
    Ok((access_token, refresh_token))
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginPayload>,
) -> Response {
    let rid = request_id(&headers);

    // Account-based (the specific account being brute-forced, attemptable
    // from any/rotating IP), IP-based (one source hammering many accounts),
    // and a tight burst window (blunts fast automated retries even before
    // either slower window trips). IP-based/burst checks are skipped when
    // the client IP cannot be trusted (see `trust_proxy`) rather than
    // keying on a spoofable header.
    let rate_key = payload.user_code.trim().to_uppercase();
    if !state.rate_limiter.check(
        &format!("login-account:{rate_key}"),
        10,
        Duration::from_secs(15 * 60),
    ) {
        return ApiError::new("RATE_LIMITED", "errors.rateLimited", rid).into_response();
    }
    if let Some(ip) = client_ip(&headers) {
        if !state
            .rate_limiter
            .check(&format!("login-ip:{ip}"), 50, Duration::from_secs(15 * 60))
        {
            return ApiError::new("RATE_LIMITED", "errors.rateLimited", rid).into_response();
        }
        if !state
            .rate_limiter
            .check(&format!("login-burst:{ip}"), 10, Duration::from_secs(60))
        {
            return ApiError::new("RATE_LIMITED", "errors.rateLimited", rid).into_response();
        }
    }

    let user = match load_user_by_code(&state.backend, &payload.user_code).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            AuditRecorder::new(
                action::AUTH_LOGIN_FAILED,
                audit_result::FAILURE,
                rid.clone(),
            )
            .headers(&headers)
            .metadata(serde_json::json!({ "userCode": rate_key, "reason": "unknown_account" }))
            .save(&state)
            .await;
            return ApiError::new("UNAUTHORIZED", "errors.invalidCredentials", rid).into_response();
        }
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };

    if !verify(&payload.password, &user.password_hash).unwrap_or(false) {
        AuditRecorder::new(
            action::AUTH_LOGIN_FAILED,
            audit_result::FAILURE,
            rid.clone(),
        )
        .actor_by_id(&user.id, &user.user_code, &user.role)
        .headers(&headers)
        .metadata(serde_json::json!({ "reason": "invalid_password" }))
        .save(&state)
        .await;
        return ApiError::new("UNAUTHORIZED", "errors.invalidCredentials", rid).into_response();
    }
    if user.is_banned {
        AuditRecorder::new(action::AUTH_LOGIN_FAILED, audit_result::DENIED, rid.clone())
            .actor_by_id(&user.id, &user.user_code, &user.role)
            .headers(&headers)
            .metadata(serde_json::json!({ "reason": "account_banned" }))
            .save(&state)
            .await;
        return ApiError::new("FORBIDDEN", "errors.accountBanned", rid).into_response();
    }
    if !user.is_approved {
        AuditRecorder::new(action::AUTH_LOGIN_FAILED, audit_result::DENIED, rid.clone())
            .actor_by_id(&user.id, &user.user_code, &user.role)
            .headers(&headers)
            .metadata(serde_json::json!({ "reason": "account_not_approved" }))
            .save(&state)
            .await;
        return ApiError::new("FORBIDDEN", "errors.accountNotApproved", rid).into_response();
    }

    let (access_token, refresh_token) = match issue_session(&state, &user, &headers).await {
        Ok(pair) => pair,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };

    AuditRecorder::new(
        action::AUTH_LOGIN_SUCCESS,
        audit_result::SUCCESS,
        rid.clone(),
    )
    .actor_by_id(&user.id, &user.user_code, &user.role)
    .headers(&headers)
    .save(&state)
    .await;

    let mut response = Json(serde_json::json!({
        "accessToken": access_token,
        "user": public_user(&user),
    }))
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie_value(&refresh_token, &headers)) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

pub async fn refresh(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rid = request_id(&headers);
    let Some(token) = extract_cookie(&headers, "refresh_token") else {
        return ApiError::new("UNAUTHORIZED", "errors.sessionExpired", rid).into_response();
    };
    let Some(claims) = decode_refresh_token(&token, &state.secrets.jwt_refresh_secret) else {
        return unauthorized(&headers);
    };

    let Ok(Some(session)) = find_session_by_family(&state.backend, &claims.family).await else {
        return unauthorized(&headers);
    };

    // A previously-revoked family being presented again means either the
    // user already logged out (harmless: still unauthorized) or a refresh
    // token was stolen and both the thief and the legitimate holder are
    // racing to use it (a genuine reuse signal) — treated identically here
    // because a stolen-and-not-yet-noticed session is exactly the case
    // this defends. Re-revoking an already-revoked family is a no-op.
    let token_hash = sha256_hex(&token);
    if session.revoked_at.is_some() || session.refresh_token_hash != token_hash {
        let _ = revoke_session_family(&state.backend, &claims.family).await;
        AuditRecorder::new(
            action::AUTH_TOKEN_REUSE_DETECTED,
            audit_result::DENIED,
            rid.clone(),
        )
        .actor_by_id(&claims.sub, "", "")
        .headers(&headers)
        .resource("session", &claims.family)
        .save(&state)
        .await;
        return unauthorized(&headers);
    }

    let Ok(expires_at) = session.expires_at.parse::<DateTime<Utc>>() else {
        return unauthorized(&headers);
    };
    if expires_at < Utc::now() {
        let _ = revoke_session(&state.backend, &session.id).await;
        return unauthorized(&headers);
    }

    let user = match load_user_by_id(&state.backend, &claims.sub).await {
        Ok(Some(user)) => user,
        _ => return unauthorized(&headers),
    };
    if user.is_banned || !user.is_approved {
        let _ = revoke_session(&state.backend, &session.id).await;
        AuditRecorder::new(
            action::AUTH_REFRESH_FAILED,
            audit_result::DENIED,
            rid.clone(),
        )
        .actor_by_id(&user.id, &user.user_code, &user.role)
        .headers(&headers)
        .save(&state)
        .await;
        return unauthorized(&headers);
    }

    let new_expires_at = Utc::now() + ChronoDuration::days(REFRESH_TOKEN_TTL_DAYS);
    let new_refresh_token = match sign_refresh(
        &user.id,
        &claims.family,
        &state.secrets.jwt_refresh_secret,
        new_expires_at,
    ) {
        Ok(token) => token,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    if rotate_session(
        &state.backend,
        &session.id,
        &sha256_hex(&new_refresh_token),
        new_expires_at,
    )
    .await
    .is_err()
    {
        return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response();
    }

    let access_token = match sign_access(&user, &state.secrets.jwt_secret) {
        Ok(token) => token,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };

    AuditRecorder::new(
        action::AUTH_REFRESH_SUCCESS,
        audit_result::SUCCESS,
        rid.clone(),
    )
    .actor_by_id(&user.id, &user.user_code, &user.role)
    .headers(&headers)
    .save(&state)
    .await;

    let mut response = Json(serde_json::json!({
        "accessToken": access_token,
        "user": public_user(&user),
    }))
    .into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie_value(&new_refresh_token, &headers)) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "status")]
enum RegistrationStatus {
    #[serde(rename = "approved")]
    Approved,
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "banned")]
    Banned,
    #[serde(rename = "not_found")]
    NotFound,
}

/// Polled by the registration form so it can move a pending applicant
/// straight to the login tab, pre-filled, the moment an admin approves
/// them — without requiring a manual page refresh. Looked up by the
/// unguessable `registrationTrackingToken` issued at registration time
/// (never by the user's own, guessable user code) so this endpoint cannot
/// be used to enumerate arbitrary accounts' status.
pub async fn registration_status(
    State(state): State<AppState>,
    axum::extract::Path(tracking_token): axum::extract::Path<String>,
) -> Response {
    let status = match load_registration_tracking_status(&state.backend, &tracking_token).await {
        Ok(Some(row)) => {
            let expired = row
                .expires_at
                .parse::<DateTime<Utc>>()
                .map(|exp| exp < Utc::now())
                .unwrap_or(true);
            if expired {
                RegistrationStatus::NotFound
            } else if row.is_banned {
                RegistrationStatus::Banned
            } else if row.is_approved {
                RegistrationStatus::Approved
            } else {
                RegistrationStatus::Pending
            }
        }
        _ => RegistrationStatus::NotFound,
    };
    Json(status).into_response()
}

/// Doesn't reset anything itself — there is no self-service reset flow.
/// It looks the account up (by user code or email) and emails the admin
/// a request to act on; the admin then sets a new password via the
/// management panel's "Düzenle" action (`admin::update_user_route`).
/// Always responds with the same success message whether or not a
/// matching account was found, so this can't be used to enumerate
/// registered user codes/emails.
pub async fn forgot_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ForgotPasswordPayload>,
) -> Response {
    let rid = request_id(&headers);
    let identifier = payload.identifier.trim();
    if identifier.is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }
    if !state.rate_limiter.check(
        &format!("forgot-password:{}", identifier.to_lowercase()),
        5,
        Duration::from_secs(15 * 60),
    ) {
        return ApiError::new("RATE_LIMITED", "errors.rateLimited", rid).into_response();
    }

    let user = if identifier.contains('@') {
        load_user_by_email(&state.backend, identifier)
            .await
            .ok()
            .flatten()
    } else {
        load_user_by_code(&state.backend, identifier)
            .await
            .ok()
            .flatten()
    };

    if let Some(user) = user {
        match user.email.as_deref() {
            // A real self-service reset: a single-use, hashed, 1-hour
            // token the account holder uses themselves — never the raw
            // token stored, never a way to skip straight to a new
            // password without proving control of the mailbox.
            Some(email) => {
                let expires_at = Utc::now() + ChronoDuration::hours(PASSWORD_RESET_TOKEN_TTL_HOURS);
                let raw_token = random_hex(32);
                if create_single_use_token(
                    &state.backend,
                    &user.id,
                    &sha256_hex(&raw_token),
                    PASSWORD_RESET_PURPOSE,
                    expires_at,
                )
                .await
                .is_ok()
                {
                    let reset_link = format!("{}/?resetToken={}", app_url(), raw_token);
                    crate::email::send_password_reset_email(
                        &user.first_name,
                        &user.last_name,
                        email,
                        &reset_link,
                    )
                    .await;
                }
            }
            // No email on file (e.g. an admin-created account) — no
            // self-service channel exists, so fall back to notifying the
            // admin, who resets the password from the management panel.
            None => {
                crate::email::send_password_reset_request(
                    &user.first_name,
                    &user.last_name,
                    &user.user_code,
                    None,
                )
                .await;
            }
        }
        AuditRecorder::new(
            action::AUTH_PASSWORD_RESET_REQUESTED,
            audit_result::SUCCESS,
            rid.clone(),
        )
        .actor_by_id(&user.id, &user.user_code, &user.role)
        .headers(&headers)
        .save(&state)
        .await;
    }

    Json(serde_json::json!({ "messageKey": "auth.forgotPasswordReceived" })).into_response()
}

fn app_url() -> String {
    std::env::var("APP_URL")
        .or_else(|_| std::env::var("RENDER_EXTERNAL_URL"))
        .unwrap_or_else(|_| "http://localhost:8080".to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordPayload {
    pub token: String,
    pub new_password: String,
}

/// Completes a self-service password reset: consumes the single-use token
/// `forgot_password` issued, sets the new password, and revokes every
/// active session for the account — a reset is exactly the kind of event
/// that should force every other signed-in device to re-authenticate.
pub async fn reset_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ResetPasswordPayload>,
) -> Response {
    let rid = request_id(&headers);
    if payload.token.trim().is_empty() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }
    if validate_password(&payload.new_password).is_some() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let token_hash = sha256_hex(payload.token.trim());
    let Ok(Some(row)) = find_single_use_token_by_hash(&state.backend, &token_hash).await else {
        return ApiError::new("VALIDATION_ERROR", "errors.invalidResetToken", rid).into_response();
    };
    if row.purpose != PASSWORD_RESET_PURPOSE || row.consumed_at.is_some() {
        return ApiError::new("VALIDATION_ERROR", "errors.invalidResetToken", rid).into_response();
    }
    let Ok(expires_at) = row.expires_at.parse::<DateTime<Utc>>() else {
        return ApiError::new("VALIDATION_ERROR", "errors.invalidResetToken", rid).into_response();
    };
    if expires_at < Utc::now() {
        return ApiError::new("VALIDATION_ERROR", "errors.invalidResetToken", rid).into_response();
    }
    // Single-use: consumed before the password is even changed, so a
    // concurrent replay of the same token can never land twice.
    if !consume_single_use_token(&state.backend, &row.id, "reset")
        .await
        .unwrap_or(false)
    {
        return ApiError::new("VALIDATION_ERROR", "errors.invalidResetToken", rid).into_response();
    }

    let hashed = match hash(&payload.new_password, DEFAULT_COST) {
        Ok(v) => v,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    let Ok(Some(user)) = update_user_password(&state.backend, &row.user_id, &hashed).await else {
        return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response();
    };
    let _ = revoke_all_sessions_for_user(&state.backend, &user.id).await;

    AuditRecorder::new(
        action::AUTH_PASSWORD_RESET_COMPLETED,
        audit_result::SUCCESS,
        rid,
    )
    .actor_by_id(&user.id, &user.user_code, &user.role)
    .headers(&headers)
    .save(&state)
    .await;

    Json(serde_json::json!({ "messageKey": "auth.passwordResetSuccess" })).into_response()
}

fn cleared_cookie() -> HeaderValue {
    HeaderValue::from_static("refresh_token=; Path=/; HttpOnly; Max-Age=0; SameSite=Strict")
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rid = request_id(&headers);
    // Best-effort: revoke the session this refresh token belongs to. Any
    // failure to decode/find it still results in the cookie being cleared
    // — logout must never appear to fail from the client's perspective.
    if let Some(token) = extract_cookie(&headers, "refresh_token") {
        if let Some(claims) = decode_refresh_token(&token, &state.secrets.jwt_refresh_secret) {
            if let Ok(Some(session)) = find_session_by_family(&state.backend, &claims.family).await
            {
                let _ = revoke_session(&state.backend, &session.id).await;
                AuditRecorder::new(action::AUTH_LOGOUT, audit_result::SUCCESS, rid)
                    .actor_by_id(&claims.sub, "", "")
                    .headers(&headers)
                    .resource("session", &claims.family)
                    .save(&state)
                    .await;
            }
        }
    }
    let mut response = Json(serde_json::json!({ "messageKey": "auth.loggedOut" })).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cleared_cookie());
    response
}

/// Revokes every session belonging to the authenticated user — "log out
/// everywhere". Requires a currently-valid access token; the refresh
/// cookie on this device is cleared same as ordinary logout.
pub async fn logout_all(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return unauthorized(&headers);
    };
    let _ = revoke_all_sessions_for_user(&state.backend, &claims.id).await;
    AuditRecorder::new(action::AUTH_LOGOUT_ALL, audit_result::SUCCESS, rid)
        .actor(&claims)
        .headers(&headers)
        .save(&state)
        .await;
    let mut response =
        Json(serde_json::json!({ "messageKey": "auth.loggedOutAll" })).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, cleared_cookie());
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_GUARD: Mutex<()> = Mutex::new(());

    fn headers(origin: Option<&str>, host: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(origin) = origin {
            h.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
        }
        if let Some(host) = host {
            h.insert(header::HOST, HeaderValue::from_str(host).unwrap());
        }
        h
    }

    #[test]
    fn same_origin_web_visit_is_not_cross_origin() {
        let h = headers(
            Some("https://anatolia-bis.onrender.com"),
            Some("anatolia-bis.onrender.com"),
        );
        assert!(!is_cross_origin_request(&h));
    }

    #[test]
    fn different_host_is_cross_origin() {
        let h = headers(
            Some("http://127.0.0.1:1420"),
            Some("anatolia-bis.onrender.com"),
        );
        assert!(is_cross_origin_request(&h));
    }

    #[test]
    fn missing_origin_header_defaults_to_same_origin() {
        let h = headers(None, Some("anatolia-bis.onrender.com"));
        assert!(!is_cross_origin_request(&h));
    }

    #[test]
    fn dev_cookie_is_always_strict() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("RENDER");
        std::env::remove_var("NODE_ENV");
        let h = headers(Some("http://127.0.0.1:1420"), Some("localhost:8080"));
        assert!(cookie_value("tok", &h).contains("SameSite=Strict"));
    }

    #[test]
    fn prod_same_origin_cookie_is_lax_not_none() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("RENDER", "1");
        let h = headers(
            Some("https://anatolia-bis.onrender.com"),
            Some("anatolia-bis.onrender.com"),
        );
        let cookie = cookie_value("tok", &h);
        std::env::remove_var("RENDER");
        assert!(cookie.contains("SameSite=Lax"), "got: {cookie}");
        assert!(cookie.contains("Secure"));
    }

    #[test]
    fn prod_cross_origin_cookie_is_none() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("RENDER", "1");
        let h = headers(
            Some("http://127.0.0.1:1420"),
            Some("anatolia-bis.onrender.com"),
        );
        let cookie = cookie_value("tok", &h);
        std::env::remove_var("RENDER");
        assert!(cookie.contains("SameSite=None"), "got: {cookie}");
    }

    #[test]
    fn password_validation_rejects_missing_classes() {
        assert!(validate_password("short1!").is_some());
        assert!(validate_password("alllowercase1!").is_some());
        assert!(validate_password("ALLUPPERCASE1!").is_some());
        assert!(validate_password("NoDigitsHere!").is_some());
        assert!(validate_password("NoSpecial1Chars").is_some());
        assert!(validate_password("Valid1Password!").is_none());
    }

    #[test]
    fn client_ip_is_ignored_without_trusted_proxy() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("RENDER");
        std::env::remove_var("NODE_ENV");
        std::env::remove_var("TRUST_PROXY");
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.5"));
        assert_eq!(client_ip(&h), None);
    }

    #[test]
    fn client_ip_is_read_when_proxy_trusted() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("RENDER");
        std::env::remove_var("NODE_ENV");
        std::env::set_var("TRUST_PROXY", "true");
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.5, 10.0.0.1"),
        );
        let ip = client_ip(&h);
        std::env::remove_var("TRUST_PROXY");
        assert_eq!(ip.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn refresh_token_round_trips_and_carries_family() {
        let secret = "test-refresh-secret-not-for-prod-use-only";
        let expires_at = Utc::now() + ChronoDuration::days(REFRESH_TOKEN_TTL_DAYS);
        let token = sign_refresh("user-1", "family-1", secret, expires_at).unwrap();
        let claims = decode_refresh_token(&token, secret).expect("token should decode");
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.family, "family-1");
    }

    #[test]
    fn refresh_token_signed_with_wrong_secret_is_rejected() {
        let expires_at = Utc::now() + ChronoDuration::days(REFRESH_TOKEN_TTL_DAYS);
        let token = sign_refresh("user-1", "family-1", "secret-a", expires_at).unwrap();
        assert!(decode_refresh_token(&token, "secret-b").is_none());
    }
}
