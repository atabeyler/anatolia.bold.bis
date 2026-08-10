use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

/// A client-supplied `x-request-id` is echoed back into responses and
/// audit records, so it must be bounded before that happens — an
/// unvalidated header could otherwise be used to smuggle oversized or
/// control-character data into logs and audit rows. Anything outside a
/// conservative length/charset is treated the same as a missing header: a
/// fresh UUID is generated instead, rather than rejecting the request over
/// what is, at worst, a client-side logging nuisance.
const MAX_REQUEST_ID_LEN: usize = 128;

pub fn request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|v| {
            !v.is_empty()
                && v.len() <= MAX_REQUEST_ID_LEN
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// Common API error body. The frontend performs localization from
/// `message_key`; `code` is a stable, machine-readable identifier that
/// must never change once shipped.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiError {
    pub code: &'static str,
    pub message_key: &'static str,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub fn new(code: &'static str, message_key: &'static str, request_id: String) -> Self {
        Self {
            code,
            message_key,
            request_id,
            details: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    fn status_code(&self) -> StatusCode {
        match self.code {
            "VALIDATION_ERROR" => StatusCode::BAD_REQUEST,
            // Probe-image validation failures (image_validation.rs) — the
            // client sent something wrong, not the server failing.
            "IMAGE_TOO_LARGE"
            | "UNSUPPORTED_IMAGE_TYPE"
            | "IMAGE_DECODE_FAILED"
            | "IMAGE_DIMENSIONS_INVALID" => StatusCode::BAD_REQUEST,
            "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
            "FORBIDDEN" => StatusCode::FORBIDDEN,
            "NOT_FOUND" => StatusCode::NOT_FOUND,
            "CONFLICT" | "LAST_ADMIN_PROTECTED" => StatusCode::CONFLICT,
            "RATE_LIMITED" => StatusCode::TOO_MANY_REQUESTS,
            "INVALID_MFA_CODE" => StatusCode::UNAUTHORIZED,
            "MFA_ENROLLMENT_NOT_STARTED" | "MFA_NOT_ENABLED" | "MFA_ALREADY_ENABLED" => {
                StatusCode::CONFLICT
            }
            "MFA_EMAIL_NOT_AVAILABLE" => StatusCode::BAD_REQUEST,
            "SAME_REVIEWER_FORBIDDEN" => StatusCode::CONFLICT,
            // Real biometric-pipeline rejections (biometric/mod.rs's
            // `BiometricError`) — the probe image itself is unusable, not
            // a server failure, so 422 rather than 400/500.
            "NO_FACE_DETECTED"
            | "MULTIPLE_FACES_DETECTED"
            | "FACE_TOO_SMALL"
            | "IMAGE_TOO_BLURRY"
            | "EXCESSIVE_POSE"
            | "POOR_LIGHTING"
            | "LOW_FACE_QUALITY" => StatusCode::UNPROCESSABLE_ENTITY,
            "BIOMETRIC_PROVIDER_UNAVAILABLE" => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        (status, Json(self)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", value.parse().unwrap());
        headers
    }

    #[test]
    fn a_well_formed_request_id_is_echoed_back_unchanged() {
        let headers = headers_with("client-req-abc123_9");
        assert_eq!(request_id(&headers), "client-req-abc123_9");
    }

    #[test]
    fn a_missing_header_falls_back_to_a_generated_uuid() {
        let id = request_id(&HeaderMap::new());
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn an_oversized_request_id_is_replaced_with_a_generated_uuid() {
        let oversized = "a".repeat(MAX_REQUEST_ID_LEN + 1);
        let id = request_id(&headers_with(&oversized));
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn a_request_id_with_disallowed_characters_is_replaced() {
        let headers = headers_with("has spaces/and;stuff");
        let id = request_id(&headers);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }
}
