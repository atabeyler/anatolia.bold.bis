use axum::extract::Request;
use axum::http::header::{HeaderValue, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};
use axum::middleware::Next;
use axum::response::Response;

use crate::config::is_production;

/// Matches the actual Vite production build: no inline `<script>`/`<style>`
/// tags, no `dangerouslySetInnerHTML`, external hashed JS/CSS bundles
/// only. Google Fonts is the one third-party origin the app loads
/// (`client/index.html`). Same-origin API only — the built frontend is
/// always served from the same origin as the API (see main.rs), so
/// `connect-src 'self'` is correct in production; a cross-origin
/// `VITE_API_BASE_URL` is a local-dev-only configuration and does not
/// receive this header from the dev server anyway.
const CONTENT_SECURITY_POLICY: &str = concat!(
    "default-src 'self'; ",
    "base-uri 'self'; ",
    "frame-ancestors 'none'; ",
    "object-src 'none'; ",
    "form-action 'self'; ",
    "script-src 'self'; ",
    "style-src 'self' https://fonts.googleapis.com; ",
    "img-src 'self' data:; ",
    "font-src 'self' https://fonts.gstatic.com; ",
    "connect-src 'self'; ",
);

/// Explicit deny-by-default for browser features this app does not use.
/// `geolocation=(self)` stays enabled: the login screen requests it
/// deliberately (see `hooks/useGeolocation.ts`) to stamp searches with a
/// location. Camera is off until a real capture-in-browser feature ships
/// — enable it only alongside that feature, scoped to `(self)`.
const PERMISSIONS_POLICY: &str = "microphone=(), camera=(), payment=(), usb=(), geolocation=(self)";

/// Baseline security headers applied to every response. Stack traces are
/// never exposed to clients regardless of build profile; error responses
/// only ever carry the stable ApiError shape (see error.rs).
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static(PERMISSIONS_POLICY),
    );

    // HSTS instructs the browser to only ever speak HTTPS to this host —
    // meaningless (and actively unhelpful) advice on a plain-HTTP local
    // dev server, so only sent in production, where the deploy is HTTPS.
    if is_production() {
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
    }

    response
}
