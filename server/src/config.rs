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
const DEV_MFA_TOKEN_SECRET: &str = "anatolia-bis-local-mfa-secret-dev-only-not-for-prod";
/// 32 bytes of fixed hex, used only outside production — see
/// `resolve_national_id_key`.
const DEV_NATIONAL_ID_ENCRYPTION_KEY: &str =
    "616e61746f6c69612d6269732d6e61746c2d69642d6465762d6b657921212121";

/// Roles required to have MFA enabled before login can complete, when
/// `MFA_REQUIRED_ROLES` is unset — see `mfa.rs`.
const DEFAULT_MFA_REQUIRED_ROLES: &[&str] = &["SYSTEM_ADMIN", "SECURITY_ADMIN", "REVIEWER"];

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
    pub mfa_token_secret: String,
    /// AES-256-GCM key for encrypting national ID numbers at rest — see
    /// `national_id.rs`. Always exactly 32 bytes.
    pub national_id_encryption_key: [u8; 32],
    pub search_default_top_k: i64,
    pub search_max_top_k: i64,
    /// Which `BiometricProvider` implementation to run — see
    /// `biometric.rs`. Only `"mock"` exists today; any other value is a
    /// hard startup failure until a real provider ships.
    pub biometric_provider: String,
    /// Four-eyes review policy (madde 15): when `true`, a candidate's
    /// first confirm/reject decision only moves it to
    /// `needs_second_review`; a second, *different* reviewer's decision
    /// is what actually finalizes it. See `db::record_review_decision`.
    pub require_second_review: bool,
    /// Roles that must enroll in TOTP MFA before they can complete login —
    /// see `mfa.rs`. `MFA_REQUIRED_ROLES` (comma-separated); defaults to
    /// `SYSTEM_ADMIN,SECURITY_ADMIN,REVIEWER`. An empty value
    /// (`MFA_REQUIRED_ROLES=`) disables mandatory MFA entirely — voluntary
    /// enrollment remains available to every role regardless.
    pub mfa_required_roles: Vec<String>,
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
        let mfa_token_secret = resolve_secret("MFA_TOKEN_SECRET", DEV_MFA_TOKEN_SECRET, production);
        let national_id_encryption_key = resolve_national_id_key(production);

        let mfa_required_roles = match env::var("MFA_REQUIRED_ROLES") {
            Ok(value) => value
                .split(',')
                .map(str::trim)
                .filter(|role| !role.is_empty())
                .map(str::to_string)
                .collect(),
            Err(_) => DEFAULT_MFA_REQUIRED_ROLES
                .iter()
                .map(|role| role.to_string())
                .collect(),
        };

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

        let biometric_provider = resolve_biometric_provider(production);
        let require_second_review = env::var("REQUIRE_SECOND_REVIEW")
            .map(|v| v == "true")
            .unwrap_or(false);

        Self {
            port,
            allowed_origins,
            jwt_secret,
            jwt_refresh_secret,
            approval_token_secret,
            mfa_token_secret,
            national_id_encryption_key,
            search_default_top_k,
            search_max_top_k,
            biometric_provider,
            mfa_required_roles,
            require_second_review,
        }
    }
}

/// `BIOMETRIC_PROVIDER` (default `"mock"`) selects the `BiometricProvider`
/// implementation. Two exist: `"mock"` (deterministic, non-biometric —
/// see `biometric/mod.rs`) and `"onnx"` (real YuNet/SFace inference via
/// ONNX Runtime — see `biometric/onnx_provider.rs`). Silently running the
/// mock, non-biometric provider in production would let a deployment look
/// fully functional while every "match" is actually a deterministic hash
/// of the uploaded bytes — CLAUDE.md explicitly forbids this. Production
/// therefore requires `ALLOW_MOCK_BIOMETRICS=true` as an explicit,
/// conscious override before it will start with the mock provider; any
/// value other than `"mock"`/`"onnx"` is a hard failure in any
/// environment.
fn resolve_biometric_provider(production: bool) -> String {
    let provider = env::var("BIOMETRIC_PROVIDER")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "mock".to_string());

    if provider != "mock" && provider != "onnx" {
        panic!(
            "BIOMETRIC_PROVIDER={provider} is not implemented — only \"mock\" and \"onnx\" exist \
             today; refusing to start with an unknown biometric provider"
        );
    }

    if production && provider == "mock" {
        let allow_mock = env::var("ALLOW_MOCK_BIOMETRICS")
            .map(|v| v == "true")
            .unwrap_or(false);
        if !allow_mock {
            panic!(
                "BIOMETRIC_PROVIDER=mock in production requires an explicit \
                 ALLOW_MOCK_BIOMETRICS=true override — refusing to silently run a \
                 non-biometric mock provider in production. Every \"match\" it returns is a \
                 deterministic hash of the uploaded bytes, not a real face comparison."
            );
        }
    }

    provider
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

/// Resolves `NATIONAL_ID_ENCRYPTION_KEY` — 64 hex characters (32 raw
/// bytes) for AES-256-GCM. In production, missing/malformed/wrong-length
/// is a hard startup failure, matching the other secrets above.
fn resolve_national_id_key(production: bool) -> [u8; 32] {
    let hex_value = match env::var("NATIONAL_ID_ENCRYPTION_KEY") {
        Ok(value) if !value.trim().is_empty() => value,
        _ if production => {
            panic!(
                "NATIONAL_ID_ENCRYPTION_KEY is required in production and was not set; \
                 refusing to start"
            );
        }
        _ => DEV_NATIONAL_ID_ENCRYPTION_KEY.to_string(),
    };
    let decoded = hex::decode(hex_value.trim()).unwrap_or_else(|_| {
        if production {
            panic!(
                "NATIONAL_ID_ENCRYPTION_KEY must be 64 hex characters (32 bytes); \
                 refusing to start in production with a malformed key"
            );
        }
        Vec::new()
    });
    match <[u8; 32]>::try_from(decoded.as_slice()) {
        Ok(key) => key,
        Err(_) if production => panic!(
            "NATIONAL_ID_ENCRYPTION_KEY must decode to exactly 32 bytes; \
             refusing to start in production with a key of the wrong length"
        ),
        Err(_) => hex::decode(DEV_NATIONAL_ID_ENCRYPTION_KEY)
            .expect("DEV_NATIONAL_ID_ENCRYPTION_KEY is a fixed, valid hex constant")
            .try_into()
            .expect("DEV_NATIONAL_ID_ENCRYPTION_KEY is a fixed 32-byte constant"),
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

    #[test]
    fn dev_mode_defaults_to_mock_without_override() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("BIOMETRIC_PROVIDER");
        env::remove_var("ALLOW_MOCK_BIOMETRICS");
        assert_eq!(resolve_biometric_provider(false), "mock");
    }

    #[test]
    #[should_panic(expected = "requires an explicit ALLOW_MOCK_BIOMETRICS=true override")]
    fn production_without_override_panics() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("BIOMETRIC_PROVIDER");
        env::remove_var("ALLOW_MOCK_BIOMETRICS");
        resolve_biometric_provider(true);
    }

    #[test]
    fn production_with_explicit_override_succeeds() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("BIOMETRIC_PROVIDER");
        env::set_var("ALLOW_MOCK_BIOMETRICS", "true");
        assert_eq!(resolve_biometric_provider(true), "mock");
        env::remove_var("ALLOW_MOCK_BIOMETRICS");
    }

    #[test]
    #[should_panic(expected = "is not implemented")]
    fn unknown_provider_panics_even_outside_production() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("BIOMETRIC_PROVIDER", "not-a-real-provider");
        resolve_biometric_provider(false);
    }

    #[test]
    fn onnx_provider_is_accepted_without_the_mock_override() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("BIOMETRIC_PROVIDER", "onnx");
        env::remove_var("ALLOW_MOCK_BIOMETRICS");
        assert_eq!(resolve_biometric_provider(true), "onnx");
        env::remove_var("BIOMETRIC_PROVIDER");
    }

    #[test]
    fn mfa_required_roles_defaults_to_the_three_privileged_roles() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("MFA_REQUIRED_ROLES");
        let config = Config::from_env();
        assert_eq!(
            config.mfa_required_roles,
            vec!["SYSTEM_ADMIN", "SECURITY_ADMIN", "REVIEWER"]
        );
    }

    #[test]
    fn mfa_required_roles_parses_a_custom_comma_separated_list() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("MFA_REQUIRED_ROLES", "SYSTEM_ADMIN, OPERATOR");
        let config = Config::from_env();
        env::remove_var("MFA_REQUIRED_ROLES");
        assert_eq!(config.mfa_required_roles, vec!["SYSTEM_ADMIN", "OPERATOR"]);
    }

    #[test]
    fn national_id_key_falls_back_to_dev_default_outside_production() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("NATIONAL_ID_ENCRYPTION_KEY");
        assert_eq!(resolve_national_id_key(false).len(), 32);
    }

    #[test]
    #[should_panic(expected = "NATIONAL_ID_ENCRYPTION_KEY is required in production")]
    fn national_id_key_missing_in_production_panics() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::remove_var("NATIONAL_ID_ENCRYPTION_KEY");
        resolve_national_id_key(true);
    }

    #[test]
    #[should_panic(expected = "must decode to exactly 32 bytes")]
    fn national_id_key_wrong_length_in_production_panics() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("NATIONAL_ID_ENCRYPTION_KEY", "aabbcc");
        resolve_national_id_key(true);
    }

    #[test]
    fn national_id_key_valid_hex_in_production_succeeds() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        let key_hex = "a".repeat(64);
        env::set_var("NATIONAL_ID_ENCRYPTION_KEY", &key_hex);
        let key = resolve_national_id_key(true);
        env::remove_var("NATIONAL_ID_ENCRYPTION_KEY");
        assert_eq!(key.len(), 32);
        assert_eq!(key[0], 0xaa);
    }

    #[test]
    fn mfa_required_roles_empty_value_disables_mandatory_mfa() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("MFA_REQUIRED_ROLES", "");
        let config = Config::from_env();
        env::remove_var("MFA_REQUIRED_ROLES");
        assert!(config.mfa_required_roles.is_empty());
    }
}
