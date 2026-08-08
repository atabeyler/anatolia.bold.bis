use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::db::{create_user, load_user_by_code, load_user_by_id, AppState, UserRow};
use crate::error::ApiError;
use crate::roles;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub id: String,
    pub user_code: String,
    pub email: String,
    pub role: String,
    pub exp: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPayload {
    pub first_name: String,
    pub last_name: String,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicUser {
    pub id: String,
    pub user_code: String,
    pub email: String,
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

// Falls back to a fixed local-development secret so `cargo test`/`cargo
// run` work with zero setup. Production (Render) must set JWT_SECRET and
// JWT_REFRESH_SECRET explicitly — see docs/ENVIRONMENT.md.
fn access_secret() -> String {
    std::env::var("JWT_SECRET").unwrap_or_else(|_| "anatolia-bis-local-access-secret".to_string())
}

fn refresh_secret() -> String {
    std::env::var("JWT_REFRESH_SECRET").unwrap_or_else(|_| "anatolia-bis-local-refresh-secret".to_string())
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

fn sign_access(user: &UserRow) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        id: user.id.clone(),
        user_code: user.user_code.clone(),
        email: user.email.clone(),
        role: user.role.clone(),
        exp: (Utc::now().timestamp() + 15 * 60) as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(access_secret().as_bytes()))
}

fn sign_refresh(user_id: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        id: user_id.to_string(),
        user_code: String::new(),
        email: String::new(),
        role: String::new(),
        exp: (Utc::now().timestamp() + 30 * 24 * 60 * 60) as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(refresh_secret().as_bytes()))
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
    std::env::var("NODE_ENV").map(|v| v == "production").unwrap_or(false) || std::env::var("RENDER").is_ok()
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
        30 * 24 * 60 * 60,
        if is_production() { " Secure;" } else { "" },
    )
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .map(|part| part.trim())
        .find_map(|part| part.strip_prefix(&format!("{name}=")).map(|v| v.to_string()))
}

pub fn decode_access_token(token: &str) -> Option<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(access_secret().as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .ok()
    .map(|data| data.claims)
}

fn decode_refresh_token(token: &str) -> Option<Claims> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(refresh_secret().as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .ok()
    .map(|data| data.claims)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApprovalClaims {
    pub user_id: String,
    pub purpose: String,
    pub exp: usize,
}

/// Signs a link a pending registration can be approved/rejected through
/// directly from the admin's email, without needing to be logged in —
/// possession of this token (mailed only to `ADMIN_EMAIL`) is the
/// authorization. Reuses the refresh-token secret rather than adding a new
/// one; distinct from a login/refresh token by shape.
pub fn sign_approval_token(user_id: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = ApprovalClaims {
        user_id: user_id.to_string(),
        purpose: "registration_approval".to_string(),
        exp: (Utc::now().timestamp() + 7 * 24 * 60 * 60) as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(refresh_secret().as_bytes()))
}

pub fn decode_approval_token(token: &str) -> Option<String> {
    let claims = decode::<ApprovalClaims>(
        token,
        &DecodingKey::from_secret(refresh_secret().as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .ok()?
    .claims;
    if claims.purpose != "registration_approval" {
        return None;
    }
    Some(claims.user_id)
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(|s| s.to_string())
}

pub fn auth_user_from_headers(headers: &HeaderMap) -> Option<Claims> {
    decode_access_token(&bearer_token(headers)?)
}

pub fn require_role(headers: &HeaderMap, allowed: &[&str]) -> bool {
    auth_user_from_headers(headers)
        .map(|claims| allowed.contains(&claims.role.as_str()))
        .unwrap_or(false)
}

fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

fn unauthorized(headers: &HeaderMap) -> Response {
    ApiError::new("UNAUTHORIZED", "errors.unauthorized", request_id(headers)).into_response()
}

pub async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(claims) = auth_user_from_headers(&headers) else {
        return unauthorized(&headers);
    };
    match load_user_by_id(&state.backend, &claims.id).await {
        Ok(Some(user)) => Json(public_user(&user)).into_response(),
        _ => unauthorized(&headers),
    }
}

pub async fn register(State(state): State<AppState>, headers: HeaderMap, Json(payload): Json<RegisterPayload>) -> Response {
    let rid = request_id(&headers);

    // Keyed globally (not per-key): an attacker controls every field in
    // this payload, so a per-key limit is trivially bypassed by varying
    // user_code/email each time. Every registration also fires an admin
    // notification email, so unthrottled spam floods the admin's inbox.
    if !state.rate_limiter.check("register", 20, Duration::from_secs(15 * 60)) {
        return ApiError::new("RATE_LIMITED", "errors.rateLimited", rid).into_response();
    }

    if payload.first_name.trim().is_empty()
        || payload.last_name.trim().is_empty()
        || payload.email.trim().is_empty()
        || payload.password.is_empty()
        || payload.user_code.trim().is_empty()
    {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let code = payload.user_code.trim().to_uppercase();
    if !(4..=20).contains(&code.len()) || !code.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    if validate_password(&payload.password).is_some() {
        return ApiError::new("VALIDATION_ERROR", "errors.validation", rid).into_response();
    }

    let hashed = match hash(&payload.password, DEFAULT_COST) {
        Ok(v) => v,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };

    match create_user(
        &state.backend,
        &code,
        &payload.email.trim().to_lowercase(),
        payload.first_name.trim(),
        payload.last_name.trim(),
        &hashed,
        roles::PENDING,
        false,
    )
    .await
    {
        Ok(Some(user)) => {
            if let Ok(token) = sign_approval_token(&user.id) {
                crate::email::send_admin_registration_notification(crate::email::RegistrationInfo {
                    first_name: &user.first_name,
                    last_name: &user.last_name,
                    email: &user.email,
                    user_code: &user.user_code,
                    approval_token: &token,
                })
                .await;
            }
            (StatusCode::CREATED, Json(serde_json::json!({ "messageKey": "auth.registrationPending" }))).into_response()
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

pub async fn login(State(state): State<AppState>, headers: HeaderMap, Json(payload): Json<LoginPayload>) -> Response {
    let rid = request_id(&headers);

    // Keyed by user_code (not IP): the actual threat is brute-forcing a
    // specific account's password, attemptable from any/rotating IP but
    // not without the account's own code.
    let rate_key = payload.user_code.trim().to_uppercase();
    if !state.rate_limiter.check(&format!("login:{rate_key}"), 10, Duration::from_secs(15 * 60)) {
        return ApiError::new("RATE_LIMITED", "errors.rateLimited", rid).into_response();
    }

    let user = match load_user_by_code(&state.backend, &payload.user_code).await {
        Ok(Some(user)) => user,
        Ok(None) => return ApiError::new("UNAUTHORIZED", "errors.invalidCredentials", rid).into_response(),
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };

    if !verify(&payload.password, &user.password_hash).unwrap_or(false) {
        return ApiError::new("UNAUTHORIZED", "errors.invalidCredentials", rid).into_response();
    }
    if user.is_banned {
        return ApiError::new("FORBIDDEN", "errors.accountBanned", rid).into_response();
    }
    if !user.is_approved {
        return ApiError::new("FORBIDDEN", "errors.accountNotApproved", rid).into_response();
    }

    let access_token = match sign_access(&user) {
        Ok(token) => token,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    let refresh_token = match sign_refresh(&user.id) {
        Ok(token) => token,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };

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
    let Some(claims) = decode_refresh_token(&token) else {
        return unauthorized(&headers);
    };
    let user = match load_user_by_id(&state.backend, &claims.id).await {
        Ok(Some(user)) => user,
        _ => return unauthorized(&headers),
    };
    if user.is_banned || !user.is_approved {
        return unauthorized(&headers);
    }
    let access_token = match sign_access(&user) {
        Ok(token) => token,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    Json(serde_json::json!({
        "accessToken": access_token,
        "user": public_user(&user),
    }))
    .into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "status")]
enum PendingStatus {
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
/// them — without requiring a manual page refresh.
pub async fn pending_status(State(state): State<AppState>, axum::extract::Path(user_code): axum::extract::Path<String>) -> Response {
    let status = match load_user_by_code(&state.backend, &user_code).await {
        Ok(Some(user)) if user.is_banned => PendingStatus::Banned,
        Ok(Some(user)) if user.is_approved => PendingStatus::Approved,
        Ok(Some(_)) => PendingStatus::Pending,
        Ok(None) => PendingStatus::NotFound,
        Err(_) => PendingStatus::NotFound,
    };
    Json(status).into_response()
}

pub async fn logout() -> Response {
    let mut response = Json(serde_json::json!({ "messageKey": "auth.loggedOut" })).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("refresh_token=; Path=/; HttpOnly; Max-Age=0; SameSite=Strict"),
    );
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
        let h = headers(Some("https://anatolia-bis.onrender.com"), Some("anatolia-bis.onrender.com"));
        assert!(!is_cross_origin_request(&h));
    }

    #[test]
    fn different_host_is_cross_origin() {
        let h = headers(Some("http://127.0.0.1:1420"), Some("anatolia-bis.onrender.com"));
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
        let h = headers(Some("http://127.0.0.1:1420"), Some("anatolia-bis.onrender.com"));
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
}
