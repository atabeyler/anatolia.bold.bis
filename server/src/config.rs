use std::env;

/// Minimum byte length a production JWT/approval secret must meet. 32
/// bytes (256 bits) is the conventional floor for an HMAC-SHA256 signing
/// key — anything shorter is brute-forceable with commodity hardware.
const MIN_SECRET_BYTES: usize = 32;

/// Fixed values used only when `is_production()` is false (local dev,
/// `cargo test`). Never used once the app decides it is running in
/// production — see `Config::from_env`.
const DEV_JWT_SECRET: &str = "anatolia-bis-local-access-secret-dev-only-not-for-prod";
const DEV_JWT_REFRESH_SECRET: &str = "anatolia-bis-local-refresh-secret-dev-only-not-for-prod";
const DEV_APPROVAL_TOKEN_SECRET: &str = "anatolia-bis-local-approval-secret-dev-only-not-for-prod";

/// Fallback when `SEARCH_DEFAULT_TOP_K` is unset.
const DEFAULT_SEARCH_DEFAULT_TOP_K: i64 = 10;
/// Fallback when `SEARCH_MAX_TOP_K` is unset. A client-requested `topK`
/// above this is silently clamped down, never rejected — see
/// `search::create_search_route`.
const DEFAULT_SEARCH_MAX_TOP_K: i64 = 50;

pub struct Config {
    pub port: u16,
    pub allowed_origins: Vec<String>,
    pub jwt_secret: String,
    pub jwt_refresh_secret: String,
    pub approval_token_secret: String,
    pub search_default_top_k: i64,
    pub search_max_top_k: i64,
}

/// True when this process should apply production security posture:
/// `NODE_ENV=production` explicitly, or `RENDER` (set by the Render
/// platform on every deploy, including preview/staging). Local `cargo
/// run`/`cargo test` set neither, so they get the permissive dev secrets.
pub fn is_production() -> bool {
    env::var("NODE_ENV")
        .map(|v| v == "production")
        .unwrap_or(false)
        || env::var("RENDER").is_ok()
}

impl Config {
    /// Loads and validates configuration once, at startup. Secrets are
    /// resolved here — not re-read from the environment on every token
    /// operation — so a production misconfiguration fails loudly and
    /// immediately at boot rather than surfacing later as a confusing
    /// runtime error, and so the resolved values live only in this struct's
    /// memory, never logged.
    ///
    /// # Panics
    /// In production, panics (refusing to start) if `JWT_SECRET`,
    /// `JWT_REFRESH_SECRET`, or `APPROVAL_TOKEN_SECRET` is unset or shorter
    /// than `MIN_SECRET_BYTES`. Outside production, missing secrets fall
    /// back to fixed development values so `cargo run`/`cargo test` work
    /// with zero setup.
    pub fn from_env() -> Self {
        let port = env::var("PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(8080);

        let allowed_origins = env::var("ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(str::to_string)
            .collect();

        let production = is_production();
        let jwt_secret = resolve_secret("JWT_SECRET", DEV_JWT_SECRET, production);
        let jwt_refresh_secret =
            resolve_secret("JWT_REFRESH_SECRET", DEV_JWT_REFRESH_SECRET, production);
        let approval_token_secret = resolve_secret(
            "APPROVAL_TOKEN_SECRET",
            DEV_APPROVAL_TOKEN_SECRET,
            production,
        );

        let search_max_top_k = env::var("SEARCH_MAX_TOP_K")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_SEARCH_MAX_TOP_K);
        let search_default_top_k = env::var("SEARCH_DEFAULT_TOP_K")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_SEARCH_DEFAULT_TOP_K)
            .min(search_max_top_k);

        Self {
            port,
            allowed_origins,
            jwt_secret,
            jwt_refresh_secret,
            approval_token_secret,
            search_default_top_k,
            search_max_top_k,
        }
    }
}

/// Resolves a single secret from `env_var`. In production, a missing or
/// weak value is a hard startup failure (never a silent fallback); outside
/// production, a missing value falls back to `dev_default`. The secret's
/// own value is never included in a panic message or log line.
fn resolve_secret(env_var: &'static str, dev_default: &'static str, production: bool) -> String {
    match env::var(env_var) {
        Ok(value) if !value.trim().is_empty() => {
            if production && value.len() < MIN_SECRET_BYTES {
                panic!(
                    "{env_var} is set but shorter than the required {MIN_SECRET_BYTES} bytes; \
                     refusing to start in production with a weak secret"
                );
            }
            value
        }
        _ if production => {
            panic!("{env_var} is required in production and was not set; refusing to start");
        }
        _ => dev_default.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn dev_mode_falls_back_to_fixed_secret() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("JWT_SECRET");
        assert_eq!(
            resolve_secret("JWT_SECRET", DEV_JWT_SECRET, false),
            DEV_JWT_SECRET
        );
    }

    #[test]
    #[should_panic(expected = "JWT_SECRET is required in production")]
    fn production_without_secret_panics() {
        resolve_secret("JWT_SECRET", DEV_JWT_SECRET, true);
    }

    #[test]
    #[should_panic(expected = "shorter than the required")]
    fn production_with_weak_secret_panics() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("JWT_SECRET_TEST_WEAK", "too-short");
        assert!(
            resolve_secret("JWT_SECRET_TEST_WEAK", DEV_JWT_SECRET, true).len() < MIN_SECRET_BYTES
        );
        env::remove_var("JWT_SECRET_TEST_WEAK");
    }

    #[test]
    fn production_with_strong_secret_succeeds() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let strong = "a".repeat(MIN_SECRET_BYTES);
        env::set_var("JWT_SECRET_TEST_STRONG", &strong);
        assert_eq!(
            resolve_secret("JWT_SECRET_TEST_STRONG", DEV_JWT_SECRET, true),
            strong
        );
        env::remove_var("JWT_SECRET_TEST_STRONG");
    }
}
