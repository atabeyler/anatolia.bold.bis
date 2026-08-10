//! TOTP-based multi-factor authentication.
//!
//! Two distinct flows share this module:
//!
//! - **Voluntary enrollment**: any already-authenticated user (bearer
//!   access token) may enroll, confirm, or disable MFA on their own
//!   account (`enroll`, `enroll_confirm`, `disable`).
//! - **Login-time challenge**: `auth::login` never issues a session
//!   directly for an account that has MFA enabled, or that holds a role in
//!   `MFA_REQUIRED_ROLES` without having enrolled yet (see
//!   `login_mfa_outcome`). Instead it hands back a short-lived,
//!   single-purpose JWT ("challenge token") that only ever authorizes
//!   finishing that one login — it grants no access on its own, since
//!   completing the flow still requires a valid TOTP/recovery code
//!   (`challenge_verify`) or, for first-time mandatory enrollment,
//!   completing enrollment itself (`challenge_enroll`,
//!   `challenge_enroll_confirm`). This is what makes MFA fail-closed for
//!   required roles rather than a frontend-only redirect: no code path
//!   hands out an access/refresh token pair for such an account without
//!   MFA actually being satisfied first.
//!
//! The TOTP secret is stored as-is (not hashed — verification needs to
//! recompute a code from it, not compare a fixed value) but is never
//! returned by any route after enrollment is confirmed, never logged, and
//! never placed in an audit event. Recovery codes are high-entropy bearer
//! secrets and are hashed exactly like the session/approval/reset tokens
//! elsewhere in this codebase.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use totp_rs::{Builder, Secret};

use crate::audit::{action, result as audit_result, AuditRecorder};
use crate::auth::{auth_user_from_headers, cookie_value, issue_session, public_user};
use crate::db::{AppState, UserRow};
use crate::error::{request_id, ApiError};

const ISSUER: &str = "Anatolia B.I.S.";
const CHALLENGE_TTL_MINUTES: i64 = 10;
const RECOVERY_CODE_COUNT: usize = 10;

pub const PURPOSE_LOGIN: &str = "mfa_login";
pub const PURPOSE_ENROLLMENT: &str = "mfa_enrollment";

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

/// What `auth::login` must do after a password has been verified: proceed
/// with issuing a session, or hand back one of the two MFA challenge
/// flows instead.
pub enum LoginMfaOutcome {
    NotRequired,
    /// MFA is already enabled on this account — the login must be
    /// completed with `challenge_verify`.
    ChallengeRequired,
    /// This account's role requires MFA (see `MFA_REQUIRED_ROLES`) but it
    /// has never been enrolled — the login must be completed with
    /// `challenge_enroll` + `challenge_enroll_confirm`.
    EnrollmentRequired,
}

pub async fn login_mfa_outcome(state: &AppState, user: &UserRow) -> LoginMfaOutcome {
    let enabled = crate::db::find_mfa_credential(&state.backend, &user.id)
        .await
        .ok()
        .flatten()
        .is_some_and(|row| row.enabled_at.is_some());
    if enabled {
        return LoginMfaOutcome::ChallengeRequired;
    }
    if state
        .mfa_required_roles
        .iter()
        .any(|role| role == &user.role)
    {
        return LoginMfaOutcome::EnrollmentRequired;
    }
    LoginMfaOutcome::NotRequired
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ChallengeClaims {
    user_id: String,
    purpose: String,
    exp: usize,
}

/// Signs a short-lived, single-purpose token that by itself grants no
/// access — see the module doc comment. Not tracked server-side as
/// single-use (unlike approval/reset tokens): it carries no authority
/// beyond letting its holder *attempt* a TOTP/recovery code or enrollment
/// against this user_id, which is exactly as sensitive as being allowed to
/// retry `POST /auth/login` itself.
pub fn sign_challenge_token(
    state: &AppState,
    user_id: &str,
    purpose: &str,
) -> Result<String, ApiError> {
    let claims = ChallengeClaims {
        user_id: user_id.to_string(),
        purpose: purpose.to_string(),
        exp: (Utc::now() + ChronoDuration::minutes(CHALLENGE_TTL_MINUTES)).timestamp() as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.secrets.mfa_token_secret.as_bytes()),
    )
    .map_err(|_| ApiError::new("INTERNAL_ERROR", "errors.internal", String::new()))
}

fn decode_challenge_token(state: &AppState, token: &str, expected_purpose: &str) -> Option<String> {
    let claims = decode::<ChallengeClaims>(
        token,
        &DecodingKey::from_secret(state.secrets.mfa_token_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .ok()?
    .claims;
    if claims.purpose != expected_purpose {
        return None;
    }
    Some(claims.user_id)
}

fn generate_secret() -> String {
    Secret::generate().to_base32()
}

fn build_totp(secret_b32: &str, account_name: &str) -> Option<totp_rs::Totp> {
    let secret = Secret::try_from_base32(secret_b32).ok()?;
    Builder::new()
        .with_secret(secret)
        .with_issuer(Some(ISSUER))
        .with_account_name(account_name.to_string())
        .build()
        .ok()
}

fn generate_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let mut buf = [0u8; 5];
            rand::thread_rng().fill_bytes(&mut buf);
            let hex = hex::encode(buf);
            format!("{}-{}", &hex[..5], &hex[5..])
        })
        .collect()
}

/// Begins (or restarts) enrollment for `user_id`, storing the freshly
/// generated secret as pending (not yet usable to complete a login/gate a
/// disable) until `confirm_enrollment` verifies a code against it.
async fn begin_enrollment(
    state: &AppState,
    user_id: &str,
    account_name: &str,
) -> Result<serde_json::Value, ApiError> {
    let secret = generate_secret();
    crate::db::upsert_pending_mfa_credential(&state.backend, user_id, &secret)
        .await
        .map_err(|_| ApiError::new("INTERNAL_ERROR", "errors.internal", String::new()))?;
    let totp = build_totp(&secret, account_name)
        .ok_or_else(|| ApiError::new("INTERNAL_ERROR", "errors.internal", String::new()))?;
    let otpauth_url = totp.to_url().unwrap_or_default();
    Ok(serde_json::json!({
        "secret": secret,
        "otpauthUrl": otpauth_url,
    }))
}

/// Verifies `code` against the pending secret for `user_id`, and if it
/// matches, enables the credential and issues a fresh set of recovery
/// codes (replacing any from a prior enrollment). Returns the raw
/// recovery codes — the only time they are ever visible after generation.
async fn confirm_enrollment(
    state: &AppState,
    user_id: &str,
    account_name: &str,
    code: &str,
) -> Result<Vec<String>, ApiError> {
    let Some(pending) = crate::db::find_mfa_credential(&state.backend, user_id)
        .await
        .ok()
        .flatten()
    else {
        return Err(ApiError::new(
            "MFA_ENROLLMENT_NOT_STARTED",
            "errors.mfaEnrollmentNotStarted",
            String::new(),
        ));
    };
    let Some(totp) = build_totp(&pending.secret, account_name) else {
        return Err(ApiError::new(
            "INTERNAL_ERROR",
            "errors.internal",
            String::new(),
        ));
    };
    if !totp_code_matches(&totp, code) {
        return Err(ApiError::new(
            "INVALID_MFA_CODE",
            "errors.invalidMfaCode",
            String::new(),
        ));
    }
    let enabled = crate::db::enable_mfa_credential(&state.backend, user_id, &pending.secret)
        .await
        .map_err(|_| ApiError::new("INTERNAL_ERROR", "errors.internal", String::new()))?;
    if !enabled {
        return Err(ApiError::new(
            "MFA_ENROLLMENT_NOT_STARTED",
            "errors.mfaEnrollmentNotStarted",
            String::new(),
        ));
    }
    let raw_codes = generate_recovery_codes();
    let hashes: Vec<String> = raw_codes.iter().map(|c| sha256_hex(c)).collect();
    crate::db::replace_recovery_codes(&state.backend, user_id, &hashes)
        .await
        .map_err(|_| ApiError::new("INTERNAL_ERROR", "errors.internal", String::new()))?;
    Ok(raw_codes)
}

fn totp_code_matches(totp: &totp_rs::Totp, code: &str) -> bool {
    let code = code.trim();
    if code.is_empty() {
        return false;
    }
    totp.check_current(code).is_some()
}

/// Verifies a TOTP code or, failing that, an unused recovery code, for an
/// already-enabled credential. On a recovery-code match the code is
/// consumed (single use) and `AuditRecorder` is expected to log
/// `MFA_RECOVERY_CODE_USED` by the caller (this function only reports
/// which kind matched, so the caller can decide what to audit).
enum VerifyOutcome {
    Totp,
    Recovery,
    Failed,
}

async fn verify_code(
    state: &AppState,
    user_id: &str,
    account_name: &str,
    code: &str,
) -> Result<VerifyOutcome, ApiError> {
    let Some(credential) = crate::db::find_mfa_credential(&state.backend, user_id)
        .await
        .ok()
        .flatten()
        .filter(|row| row.enabled_at.is_some())
    else {
        return Err(ApiError::new(
            "MFA_NOT_ENABLED",
            "errors.mfaNotEnabled",
            String::new(),
        ));
    };
    if let Some(totp) = build_totp(&credential.secret, account_name) {
        if totp_code_matches(&totp, code) {
            let _ = crate::db::touch_mfa_last_used(&state.backend, user_id).await;
            return Ok(VerifyOutcome::Totp);
        }
    }
    let code_hash = sha256_hex(code.trim());
    if crate::db::consume_recovery_code(&state.backend, user_id, &code_hash)
        .await
        .unwrap_or(false)
    {
        let _ = crate::db::touch_mfa_last_used(&state.backend, user_id).await;
        return Ok(VerifyOutcome::Recovery);
    }
    Ok(VerifyOutcome::Failed)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollConfirmPayload {
    pub code: String,
}

/// `POST /api/v1/auth/mfa/enroll` — voluntary enrollment start for an
/// already-authenticated user.
pub async fn enroll(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    match begin_enrollment(&state, &claims.id, &claims.user_code).await {
        Ok(body) => Json(body).into_response(),
        Err(mut err) => {
            err.request_id = rid;
            err.into_response()
        }
    }
}

/// `POST /api/v1/auth/mfa/enroll/confirm` — confirms voluntary enrollment.
pub async fn enroll_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<EnrollConfirmPayload>,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    match confirm_enrollment(&state, &claims.id, &claims.user_code, &payload.code).await {
        Ok(recovery_codes) => {
            // MANDATORY — see AuditRecorder::save_mandatory.
            if let Err(mut err) =
                AuditRecorder::new(action::MFA_ENABLED, audit_result::SUCCESS, rid.clone())
                    .actor(&claims)
                    .headers(&headers)
                    .save_mandatory(&state)
                    .await
            {
                err.request_id = rid;
                return err.into_response();
            }
            Json(serde_json::json!({ "recoveryCodes": recovery_codes })).into_response()
        }
        Err(mut err) => {
            err.request_id = rid;
            err.into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisablePayload {
    pub password: String,
    pub code: String,
}

/// `POST /api/v1/auth/mfa/disable` — requires both the account's current
/// password and a valid TOTP/recovery code, so a stolen access token alone
/// cannot turn MFA off. If this account's role is in `MFA_REQUIRED_ROLES`,
/// disabling still succeeds (the account is not locked out of its own
/// security setting) but the next login will require re-enrollment — see
/// `login_mfa_outcome`.
pub async fn disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<DisablePayload>,
) -> Response {
    let rid = request_id(&headers);
    let Some(claims) = auth_user_from_headers(&headers, &state.secrets.jwt_secret) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    let Ok(Some(user)) = crate::db::load_user_by_id(&state.backend, &claims.id).await else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    if !bcrypt::verify(&payload.password, &user.password_hash).unwrap_or(false) {
        return ApiError::new("UNAUTHORIZED", "errors.invalidCredentials", rid).into_response();
    }
    match verify_code(&state, &claims.id, &claims.user_code, &payload.code).await {
        Ok(VerifyOutcome::Failed) | Err(_) => {
            ApiError::new("INVALID_MFA_CODE", "errors.invalidMfaCode", rid).into_response()
        }
        Ok(_) => {
            if crate::db::delete_mfa_credential(&state.backend, &claims.id)
                .await
                .is_err()
            {
                return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response();
            }
            // MANDATORY — see AuditRecorder::save_mandatory.
            if let Err(mut err) =
                AuditRecorder::new(action::MFA_DISABLED, audit_result::SUCCESS, rid.clone())
                    .actor(&claims)
                    .headers(&headers)
                    .save_mandatory(&state)
                    .await
            {
                err.request_id = rid;
                return err.into_response();
            }
            Json(serde_json::json!({ "messageKey": "auth.mfa.disabled" })).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeTokenPayload {
    pub mfa_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChallengeCodePayload {
    pub mfa_token: String,
    pub code: String,
}

async fn load_user_or_unauthorized(
    state: &AppState,
    user_id: &str,
    rid: &str,
) -> Result<UserRow, Response> {
    match crate::db::load_user_by_id(&state.backend, user_id).await {
        Ok(Some(user)) if !user.is_banned && user.is_approved => Ok(user),
        _ => Err(
            ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid.to_string()).into_response(),
        ),
    }
}

/// `POST /api/v1/auth/mfa/challenge/enroll` — begins mandatory,
/// login-time enrollment for a role that requires MFA but has none yet.
pub async fn challenge_enroll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ChallengeTokenPayload>,
) -> Response {
    let rid = request_id(&headers);
    let Some(user_id) = decode_challenge_token(&state, &payload.mfa_token, PURPOSE_ENROLLMENT)
    else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    let user = match load_user_or_unauthorized(&state, &user_id, &rid).await {
        Ok(user) => user,
        Err(resp) => return resp,
    };
    match begin_enrollment(&state, &user.id, &user.user_code).await {
        Ok(body) => Json(body).into_response(),
        Err(mut err) => {
            err.request_id = rid;
            err.into_response()
        }
    }
}

/// `POST /api/v1/auth/mfa/challenge/enroll/confirm` — completes mandatory
/// enrollment and, in the same response, completes the login that
/// triggered it (issues the real session).
pub async fn challenge_enroll_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ChallengeCodePayload>,
) -> Response {
    let rid = request_id(&headers);
    let Some(user_id) = decode_challenge_token(&state, &payload.mfa_token, PURPOSE_ENROLLMENT)
    else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    let user = match load_user_or_unauthorized(&state, &user_id, &rid).await {
        Ok(user) => user,
        Err(resp) => return resp,
    };
    let recovery_codes =
        match confirm_enrollment(&state, &user.id, &user.user_code, &payload.code).await {
            Ok(codes) => codes,
            Err(mut err) => {
                err.request_id = rid;
                return err.into_response();
            }
        };
    // MANDATORY — see AuditRecorder::save_mandatory.
    if let Err(mut err) =
        AuditRecorder::new(action::MFA_ENABLED, audit_result::SUCCESS, rid.clone())
            .actor_by_id(&user.id, &user.user_code, &user.role)
            .headers(&headers)
            .save_mandatory(&state)
            .await
    {
        err.request_id = rid;
        return err.into_response();
    }
    complete_login(&state, &user, &headers, rid, Some(recovery_codes)).await
}

/// `POST /api/v1/auth/mfa/challenge/verify` — completes login for an
/// account that already has MFA enabled.
pub async fn challenge_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ChallengeCodePayload>,
) -> Response {
    let rid = request_id(&headers);
    let Some(user_id) = decode_challenge_token(&state, &payload.mfa_token, PURPOSE_LOGIN) else {
        return ApiError::new("UNAUTHORIZED", "errors.unauthorized", rid).into_response();
    };
    let user = match load_user_or_unauthorized(&state, &user_id, &rid).await {
        Ok(user) => user,
        Err(resp) => return resp,
    };

    // Brute-force guard on the code itself — independent of the login
    // rate limits already applied when the password was checked, since a
    // valid challenge token can be reused to retry codes until it expires.
    if !state.rate_limiter.check(
        &format!("mfa-verify:{}", user.id),
        8,
        Duration::from_secs(15 * 60),
    ) {
        return ApiError::new("RATE_LIMITED", "errors.rateLimited", rid).into_response();
    }

    match verify_code(&state, &user.id, &user.user_code, &payload.code).await {
        Ok(VerifyOutcome::Failed) | Err(_) => {
            AuditRecorder::new(
                action::MFA_CHALLENGE_FAILED,
                audit_result::DENIED,
                rid.clone(),
            )
            .actor_by_id(&user.id, &user.user_code, &user.role)
            .headers(&headers)
            .save(&state)
            .await;
            ApiError::new("INVALID_MFA_CODE", "errors.invalidMfaCode", rid).into_response()
        }
        Ok(VerifyOutcome::Recovery) => {
            AuditRecorder::new(
                action::MFA_RECOVERY_CODE_USED,
                audit_result::SUCCESS,
                rid.clone(),
            )
            .actor_by_id(&user.id, &user.user_code, &user.role)
            .headers(&headers)
            .save(&state)
            .await;
            complete_login(&state, &user, &headers, rid, None).await
        }
        Ok(VerifyOutcome::Totp) => complete_login(&state, &user, &headers, rid, None).await,
    }
}

async fn complete_login(
    state: &AppState,
    user: &UserRow,
    headers: &HeaderMap,
    rid: String,
    recovery_codes: Option<Vec<String>>,
) -> Response {
    let (access_token, refresh_token) = match issue_session(state, user, headers).await {
        Ok(pair) => pair,
        Err(_) => return ApiError::new("INTERNAL_ERROR", "errors.internal", rid).into_response(),
    };
    AuditRecorder::new(
        action::AUTH_LOGIN_SUCCESS,
        audit_result::SUCCESS,
        rid.clone(),
    )
    .actor_by_id(&user.id, &user.user_code, &user.role)
    .headers(headers)
    .save(state)
    .await;

    let mut body = serde_json::json!({
        "accessToken": access_token,
        "user": public_user(user),
    });
    if let Some(codes) = recovery_codes {
        body["recoveryCodes"] = serde_json::json!(codes);
    }
    let mut response = Json(body).into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&cookie_value(&refresh_token, headers)) {
        response
            .headers_mut()
            .insert(axum::http::header::SET_COOKIE, value);
    }
    response
}

/// `POST /api/v1/admin/users/:id/mfa/reset` — administrative reset:
/// removes the target account's MFA credential and recovery codes
/// entirely, forcing re-enrollment on next login. Restricted to
/// `SYSTEM_ADMIN`/`SECURITY_ADMIN` (see `permission::can_administer_users`,
/// enforced by the caller in `admin.rs`).
pub async fn admin_reset(state: &AppState, target_user_id: &str) -> Result<(), sqlx::Error> {
    crate::db::delete_mfa_credential(&state.backend, target_user_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_round_trips_through_totp() {
        let secret = generate_secret();
        let totp = build_totp(&secret, "TEST-USER").expect("valid totp");
        let code = totp.generate_current();
        assert!(totp_code_matches(&totp, &code.to_string()));
    }

    #[test]
    fn wrong_code_is_rejected() {
        let secret = generate_secret();
        let totp = build_totp(&secret, "TEST-USER").expect("valid totp");
        assert!(!totp_code_matches(&totp, "000000"));
    }

    #[test]
    fn recovery_codes_are_unique_and_well_formed() {
        let codes = generate_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        let unique: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), RECOVERY_CODE_COUNT);
        for code in &codes {
            assert_eq!(code.len(), 11); // 5 hex + '-' + 5 hex
        }
    }

    #[test]
    fn challenge_token_round_trips_with_matching_purpose() {
        let state_secret = "test-mfa-secret-not-for-prod-use-only";
        let claims = ChallengeClaims {
            user_id: "user-1".to_string(),
            purpose: PURPOSE_LOGIN.to_string(),
            exp: (Utc::now() + ChronoDuration::minutes(CHALLENGE_TTL_MINUTES)).timestamp() as usize,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(state_secret.as_bytes()),
        )
        .unwrap();
        let decoded = decode::<ChallengeClaims>(
            &token,
            &DecodingKey::from_secret(state_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .unwrap()
        .claims;
        assert_eq!(decoded.user_id, "user-1");
        assert_eq!(decoded.purpose, PURPOSE_LOGIN);
    }
}
