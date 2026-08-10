use std::sync::Arc;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool, SqlitePool};
use std::str::FromStr;
use uuid::Uuid;

use crate::config::Config;
use crate::ratelimit::{InMemoryRateLimiter, RateLimiterBackend};

// Domain modules. Each groups the tables/queries for one area of the
// system; everything else in this file is shared infrastructure
// (connection setup, schema migration, `AppState`) that every domain
// depends on rather than
// belonging to one of them. Re-exported so existing call sites
// (`crate::db::AuditEventRow`, etc.) don't need to change.
mod audit;
pub use audit::*;
mod mfa;
pub use mfa::*;
mod org;
pub use org::*;
mod biometric;
pub use biometric::*;
mod evidence;
pub use evidence::*;
mod entity_graph;
pub use entity_graph::*;
mod identity;
pub use identity::*;
mod session;
pub use session::*;

#[derive(Clone)]
pub enum DbBackend {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

/// Secrets resolved once at startup by `Config::from_env` (see
/// config.rs). Token code reads these from `AppState` rather than
/// re-reading the environment on every request.
#[derive(Clone)]
pub struct Secrets {
    pub jwt_secret: String,
    pub jwt_refresh_secret: String,
    pub approval_token_secret: String,
    pub mfa_token_secret: String,
    pub national_id_encryption_key: [u8; 32],
}

/// Search tuning resolved once at startup by `Config::from_env`.
#[derive(Clone)]
pub struct SearchLimits {
    pub default_top_k: i64,
    pub max_top_k: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub backend: DbBackend,
    pub rate_limiter: Arc<dyn RateLimiterBackend>,
    pub secrets: Arc<Secrets>,
    pub search_limits: Arc<SearchLimits>,
    /// Roles that must have MFA enabled before they can complete login —
    /// see `mfa.rs`. Configured via `MFA_REQUIRED_ROLES`.
    pub mfa_required_roles: Arc<Vec<String>>,
    /// Four-eyes review policy — see `config::Config::require_second_review`.
    pub require_second_review: bool,
    /// The active `BiometricProvider` implementation — selected by
    /// `BIOMETRIC_PROVIDER`, resolved once at startup. See
    /// `biometric/mod.rs`.
    pub biometric_provider: Arc<dyn crate::biometric::BiometricProvider>,
    /// `"mock"` or `"onnx"` — which provider `biometric_provider` actually
    /// is, kept alongside it so a health/diagnostics endpoint can report
    /// it without downcasting the trait object.
    pub biometric_provider_name: &'static str,
    /// Whether biometric search uses the indexed pgvector path or the
    /// brute-force in-memory scan — resolved once at startup by
    /// `migrate`. See `db::biometric::ensure_pgvector_index`.
    pub pgvector_search_ready: bool,
    /// OSINT/evidence provider orchestrator — see `osint/mod.rs`. Each
    /// provider slot independently selects a real or mock implementation,
    /// matching the `biometric_provider` pattern.
    pub osint_orchestrator: Arc<crate::osint::EvidenceOrchestrator>,
    /// Renders the current Prometheus snapshot for `GET /metrics` — see
    /// `metrics.rs`. The recorder itself is process-wide/global (the
    /// `metrics` crate's macros work anywhere without this handle); the
    /// handle is only needed to render a snapshot on demand.
    pub metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
}

impl AppState {
    /// Prefers a managed PostgreSQL database (`DATABASE_URL`) when
    /// configured. On Render (`RENDER_EXTERNAL_URL` is set by the platform
    /// itself), a missing `DATABASE_URL` is a loud startup failure rather
    /// than a silent fallback to a throwaway SQLite database that would
    /// look healthy while holding no real users — a Postgres outage should
    /// be a visible deploy failure, not confusing, unrequested data loss.
    /// Locally, an unset `DATABASE_URL` just falls back to a SQLite file.
    pub async fn new(config: &Config) -> Result<Self, sqlx::Error> {
        let backend = match std::env::var("DATABASE_URL") {
            Ok(url) if !url.trim().is_empty() => DbBackend::Postgres(connect_postgres(&url).await?),
            _ if std::env::var("RENDER_EXTERNAL_URL").is_ok() => {
                panic!("DATABASE_URL is required on the web deploy (RENDER_EXTERNAL_URL is set) — refusing to fall back to a throwaway SQLite database");
            }
            _ if crate::config::is_production() => {
                panic!("Production must not fall back to SQLite — set DATABASE_URL");
            }
            _ => sqlite_backend().await?,
        };
        let pgvector_search_ready = migrate(&backend).await?;
        let biometric_provider_name: &'static str = if config.biometric_provider == "onnx" {
            "onnx"
        } else {
            "mock"
        };
        let biometric_provider: Arc<dyn crate::biometric::BiometricProvider> =
            match config.biometric_provider.as_str() {
                #[cfg(feature = "onnx-provider")]
                "onnx" => Arc::new(
                    crate::biometric::OnnxBiometricProvider::initialize()
                        .await
                        .unwrap_or_else(|err| {
                            panic!(
                                "BIOMETRIC_PROVIDER=onnx but the ONNX provider failed to \
                                 initialize ({err}); refusing to start rather than silently \
                                 falling back to the mock provider"
                            )
                        }),
                ),
                #[cfg(not(feature = "onnx-provider"))]
                "onnx" => panic!(
                    "BIOMETRIC_PROVIDER=onnx but this binary was built without the \
                     \"onnx-provider\" Cargo feature; rebuild with \
                     `cargo build --features onnx-provider` on a build host that can link \
                     `ort`, or use BIOMETRIC_PROVIDER=mock — refusing to silently fall back \
                     to the mock provider"
                ),
                _ => Arc::new(crate::biometric::MockBiometricProvider),
            };
        Ok(Self {
            backend,
            rate_limiter: Arc::new(InMemoryRateLimiter::new()),
            secrets: Arc::new(Secrets {
                jwt_secret: config.jwt_secret.clone(),
                jwt_refresh_secret: config.jwt_refresh_secret.clone(),
                approval_token_secret: config.approval_token_secret.clone(),
                mfa_token_secret: config.mfa_token_secret.clone(),
                national_id_encryption_key: config.national_id_encryption_key,
            }),
            search_limits: Arc::new(SearchLimits {
                default_top_k: config.search_default_top_k,
                max_top_k: config.search_max_top_k,
            }),
            mfa_required_roles: Arc::new(config.mfa_required_roles.clone()),
            require_second_review: config.require_second_review,
            biometric_provider,
            biometric_provider_name,
            pgvector_search_ready,
            osint_orchestrator: Arc::new(crate::osint::EvidenceOrchestrator::from_env()),
            metrics_handle: crate::metrics::init(),
        })
    }

    /// An isolated, in-memory SQLite-backed state for tests (unit tests in
    /// this crate and integration tests under `tests/`, which link this
    /// crate as an ordinary dependency and so cannot see `#[cfg(test)]`
    /// items).
    pub async fn for_tests() -> Self {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::from_str("sqlite::memory:").unwrap())
            .await
            .expect("failed to open in-memory sqlite database");
        let backend = DbBackend::Sqlite(pool);
        migrate(&backend).await.expect("failed to run migrations");
        Self {
            backend,
            rate_limiter: Arc::new(InMemoryRateLimiter::new()),
            secrets: Arc::new(Secrets {
                jwt_secret: "test-access-secret-not-for-prod-use-only".to_string(),
                jwt_refresh_secret: "test-refresh-secret-not-for-prod-use-only".to_string(),
                approval_token_secret: "test-approval-secret-not-for-prod-use-only".to_string(),
                mfa_token_secret: "test-mfa-secret-not-for-prod-use-only".to_string(),
                national_id_encryption_key: [0x42u8; 32],
            }),
            search_limits: Arc::new(SearchLimits {
                default_top_k: 10,
                max_top_k: 50,
            }),
            // Empty by default so existing integration tests (most of
            // which log in as SYSTEM_ADMIN/SECURITY_ADMIN/REVIEWER to
            // exercise admin/audit/review endpoints) are not forced
            // through MFA enrollment. `server/tests/mfa.rs` builds its own
            // state with required roles set to exercise the mandatory
            // flow directly.
            mfa_required_roles: Arc::new(Vec::new()),
            require_second_review: false,
            biometric_provider: Arc::new(crate::biometric::MockBiometricProvider),
            biometric_provider_name: "mock",
            pgvector_search_ready: false,
            osint_orchestrator: Arc::new(crate::osint::EvidenceOrchestrator::mock()),
            metrics_handle: crate::metrics::init(),
        }
    }

    /// A Postgres-backed test state, for the one class of test that a
    /// SQLite in-memory database cannot exercise at all: the indexed
    /// pgvector search path (`db::biometric::search_top_k`'s Postgres
    /// branch). Requires a real, reachable Postgres with the `vector`
    /// extension installable — pass its connection string via
    /// `PGVECTOR_TEST_DATABASE_URL`. Returns `None` (never panics) when
    /// that variable isn't set, so this stays opt-in and never runs
    /// unintentionally in an environment without one — see
    /// `tests/pgvector_search.rs`.
    pub async fn for_postgres_tests() -> Option<Self> {
        let url = std::env::var("PGVECTOR_TEST_DATABASE_URL").ok()?;
        let pool = connect_postgres(&url)
            .await
            .expect("failed to connect to PGVECTOR_TEST_DATABASE_URL");
        let backend = DbBackend::Postgres(pool);
        let pgvector_search_ready = migrate(&backend).await.expect("failed to run migrations");
        Some(Self {
            backend,
            rate_limiter: Arc::new(InMemoryRateLimiter::new()),
            secrets: Arc::new(Secrets {
                jwt_secret: "test-access-secret-not-for-prod-use-only".to_string(),
                jwt_refresh_secret: "test-refresh-secret-not-for-prod-use-only".to_string(),
                approval_token_secret: "test-approval-secret-not-for-prod-use-only".to_string(),
                mfa_token_secret: "test-mfa-secret-not-for-prod-use-only".to_string(),
                national_id_encryption_key: [0x42u8; 32],
            }),
            search_limits: Arc::new(SearchLimits {
                default_top_k: 10,
                max_top_k: 50,
            }),
            mfa_required_roles: Arc::new(Vec::new()),
            require_second_review: false,
            biometric_provider: Arc::new(crate::biometric::MockBiometricProvider),
            biometric_provider_name: "mock",
            pgvector_search_ready,
            osint_orchestrator: Arc::new(crate::osint::EvidenceOrchestrator::mock()),
            metrics_handle: crate::metrics::init(),
        })
    }
}

/// Dedicated schema for this application's tables — the database this
/// connects to may be shared with another, unrelated application (e.g. on
/// a hosting plan that only permits one free-tier database per account),
/// so tables must never land in the shared `public` schema.
const PG_SCHEMA: &str = "anatolia_bis";

async fn connect_postgres(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let mut last_err: Option<sqlx::Error> = None;
    for attempt in 0..3 {
        match PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(20))
            // `SET search_path` is a per-session setting. Running it only
            // once (e.g. inside migrate()) would apply to whichever single
            // connection happened to service that one query — every other
            // connection the pool later opens would keep Postgres's
            // default search_path (which does not include PG_SCHEMA), so
            // two logically identical queries could resolve `users` to two
            // different physical tables depending on which pooled
            // connection served each one. after_connect runs this on every
            // connection the pool ever opens, so every query resolves
            // against the same schema regardless of which physical
            // connection handles it.
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::Executor::execute(
                        conn,
                        format!("SET search_path TO {PG_SCHEMA}, public").as_str(),
                    )
                    .await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await
        {
            Ok(pool) => return Ok(pool),
            Err(err) => {
                tracing::warn!(attempt, error = %err, "failed to connect to Postgres, retrying");
                last_err = Some(err);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Err(last_err.expect("at least one connection attempt must have run"))
}

async fn sqlite_backend() -> Result<DbBackend, sqlx::Error> {
    let data_dir = std::env::var("SERVER_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("data"));
    std::fs::create_dir_all(&data_dir).ok();
    let db_path = data_dir.join("dev.db");
    let options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal);
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await?;
    Ok(DbBackend::Sqlite(pool))
}

pub fn backend_name(backend: &DbBackend) -> &'static str {
    match backend {
        DbBackend::Postgres(_) => "postgres",
        DbBackend::Sqlite(_) => "sqlite",
    }
}

/// Returns whether indexed pgvector biometric search is ready (always
/// `false` for SQLite) — see `biometric::ensure_pgvector_index`.
async fn migrate(backend: &DbBackend) -> Result<bool, sqlx::Error> {
    let pgvector_ready = match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query(&format!("CREATE SCHEMA IF NOT EXISTS {PG_SCHEMA}"))
                .execute(pool)
                .await?;
            sqlx::query("CREATE EXTENSION IF NOT EXISTS pgcrypto")
                .execute(pool)
                .await?;
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_code VARCHAR(20) UNIQUE NOT NULL,
                    first_name VARCHAR(100) NOT NULL,
                    last_name VARCHAR(100) NOT NULL,
                    national_id VARCHAR(11) UNIQUE,
                    email VARCHAR(255) UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'pending',
                    is_approved BOOLEAN NOT NULL DEFAULT false,
                    is_banned BOOLEAN NOT NULL DEFAULT false,
                    ban_reason TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                "#,
            )
            .execute(pool)
            .await?;
            // The table may already exist from a deploy that predates a
            // given column (this bit us for real: national_id was added
            // after this database's `users` table already existed, so
            // CREATE TABLE IF NOT EXISTS above was a no-op and every
            // insert referencing the column failed at runtime). Patch in
            // anything still missing rather than assuming a fresh table.
            sqlx::query(
                r#"
                ALTER TABLE users
                    ADD COLUMN IF NOT EXISTS national_id VARCHAR(11)
                "#,
            )
            .execute(pool)
            .await?;
            // national_id and email are optional for admin-created accounts
            // (direct add from the management panel, no self-registration
            // TC no./email on file) — a table from before that path existed
            // may still carry the old NOT NULL constraints.
            sqlx::query("ALTER TABLE users ALTER COLUMN national_id DROP NOT NULL")
                .execute(pool)
                .await?;
            sqlx::query("ALTER TABLE users ALTER COLUMN email DROP NOT NULL")
                .execute(pool)
                .await?;
            // Encryption-at-rest for national ID numbers (see
            // national_id.rs): `national_id_encrypted` (AES-256-GCM,
            // base64) replaces the plaintext `national_id` column above for
            // every write going forward; `national_id_lookup_hash`
            // (HMAC-SHA256, deterministic) carries the duplicate-detection
            // uniqueness the old column's UNIQUE constraint provided,
            // without the database ever holding a readable value. The old
            // `national_id` column is left in place (not backfilled or
            // dropped) so any pre-existing plaintext data isn't touched by
            // a migration that can't itself decide how to re-key it; it is
            // simply never read or written by the application anymore.
            sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS national_id_encrypted TEXT")
                .execute(pool)
                .await?;
            sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS national_id_lookup_hash TEXT")
                .execute(pool)
                .await?;
            sqlx::query(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_national_id_lookup_hash \
                 ON users (national_id_lookup_hash) WHERE national_id_lookup_hash IS NOT NULL",
            )
            .execute(pool)
            .await?;
            // Unguessable pointer a pending applicant polls with instead of
            // their own (guessable) user code — see
            // auth::registration_status and the enumeration-protection note
            // on the old pending_status endpoint it replaced.
            sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS registration_tracking_token VARCHAR(64) UNIQUE")
                .execute(pool)
                .await?;
            sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS registration_tracking_expires_at TIMESTAMPTZ")
                .execute(pool)
                .await?;
            // Soft delete: an admin removing an established account (as
            // opposed to rejecting a never-approved registration, which is
            // still a hard delete — see admin::reject_user) sets this
            // instead of physically removing the row, so the account's
            // search/audit/review history keeps a resolvable actor rather
            // than an orphaned foreign key. Every read that should treat a
            // deleted account as gone filters on `deleted_at IS NULL`.
            sqlx::query("ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ")
                .execute(pool)
                .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS candidates (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    reference_code VARCHAR(20) UNIQUE NOT NULL,
                    full_name VARCHAR(200) NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS searches (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    case_reference VARCHAR(100) NOT NULL,
                    purpose TEXT NOT NULL,
                    requested_by UUID NOT NULL,
                    requested_by_name VARCHAR(200) NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'queued',
                    latitude DOUBLE PRECISION,
                    longitude DOUBLE PRECISION,
                    top_k INTEGER,
                    started_at TIMESTAMPTZ,
                    completed_at TIMESTAMPTZ,
                    failure_code TEXT,
                    failure_message_key TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                "#,
            )
            .execute(pool)
            .await?;
            // Same "table may already exist from an earlier deploy" hazard
            // as `users.national_id` — patch in columns added after
            // `searches` first shipped rather than assuming a fresh table.
            sqlx::query("ALTER TABLE searches ADD COLUMN IF NOT EXISTS top_k INTEGER")
                .execute(pool)
                .await?;
            sqlx::query("ALTER TABLE searches ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ")
                .execute(pool)
                .await?;
            sqlx::query("ALTER TABLE searches ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ")
                .execute(pool)
                .await?;
            sqlx::query("ALTER TABLE searches ADD COLUMN IF NOT EXISTS failure_code TEXT")
                .execute(pool)
                .await?;
            sqlx::query("ALTER TABLE searches ADD COLUMN IF NOT EXISTS failure_message_key TEXT")
                .execute(pool)
                .await?;
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS search_candidates (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    search_id UUID NOT NULL,
                    candidate_id UUID NOT NULL,
                    score DOUBLE PRECISION NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'pending',
                    reviewed_by UUID,
                    reviewed_by_name VARCHAR(200),
                    reviewed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                "#,
            )
            .execute(pool)
            .await?;
            // An install predating this fix has `score REAL` (32-bit) —
            // same class of bug as `sessions.rotation_counter` and
            // `searches.top_k` (see their fixes), except here it's a
            // float width mismatch: `SearchCandidateRow::score` is `f64`,
            // which sqlx's Postgres decoder rejects when reading a
            // `REAL`/float4 column. Safe to widen unconditionally — a
            // float4-to-float8 conversion never loses precision or fails.
            sqlx::query("ALTER TABLE search_candidates ALTER COLUMN score TYPE DOUBLE PRECISION")
                .execute(pool)
                .await?;
            // Same "table may already exist from an earlier deploy" hazard
            // as `users.national_id` above — patch in columns added after
            // `searches` first shipped rather than assuming a fresh table.
            sqlx::query("ALTER TABLE searches ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION")
                .execute(pool)
                .await?;
            sqlx::query("ALTER TABLE searches ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION")
                .execute(pool)
                .await?;
            // A candidate should only ever appear once per search — the
            // unique index makes that a database-enforced invariant rather
            // than one relying solely on `finalize_queued_search` never
            // inserting a duplicate. `search` history/filtering reads
            // by `created_at`, `case_reference`, and `requested_by` (see
            // `list_searches_page`), so all three get an index.
            sqlx::query(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_search_candidates_search_candidate \
                 ON search_candidates (search_id, candidate_id)",
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_searches_created_at ON searches (created_at)",
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_searches_case_reference ON searches (case_reference)",
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_searches_requested_by ON searches (requested_by)",
            )
            .execute(pool)
            .await?;

            // Append-only review history: `search_candidates.status`
            // (above) is a convenience "current status" column, but the
            // decisions that led to it must never be silently overwritten.
            // Every confirm/reject writes one new row here in addition to
            // updating that column — see search::review.
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS verification_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    search_candidate_id UUID NOT NULL,
                    reviewer_user_id UUID NOT NULL,
                    reviewer_name VARCHAR(200) NOT NULL,
                    decision VARCHAR(20) NOT NULL,
                    reason TEXT,
                    notes TEXT,
                    request_id TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_verification_events_search_candidate_id \
                 ON verification_events (search_candidate_id)",
            )
            .execute(pool)
            .await?;

            // Server-side session records backing refresh-token rotation
            // (see auth.rs). The raw refresh token is never stored — only
            // its hash — so a database read alone can never yield a usable
            // token.
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS sessions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID NOT NULL,
                    refresh_token_hash TEXT NOT NULL,
                    token_family_id UUID NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL,
                    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    revoked_at TIMESTAMPTZ,
                    user_agent TEXT,
                    ip_address TEXT,
                    rotation_counter INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)")
                .execute(pool)
                .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_token_family_id ON sessions (token_family_id)")
                .execute(pool)
                .await?;

            // Single-use, short-lived tokens for the registration
            // approve/reject email flow — deliberately separate from
            // `sessions` (a different purpose, a different secret; see
            // auth::sign_approval_token).
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS approval_tokens (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id UUID NOT NULL,
                    token_hash TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL,
                    consumed_at TIMESTAMPTZ,
                    result TEXT
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_approval_tokens_user_id ON approval_tokens (user_id)")
                .execute(pool)
                .await?;

            // Append-only. No handler ever UPDATEs or DELETEs a row here —
            // see audit.rs. `metadata` holds anything action-specific that
            // doesn't warrant its own column (never raw biometric data,
            // passwords, or tokens — see AuditService::record).
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS audit_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    "timestamp" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    actor_user_id UUID,
                    actor_user_code TEXT,
                    actor_role TEXT,
                    action TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    case_reference TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    result TEXT NOT NULL,
                    source TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    metadata JSONB,
                    organization_id UUID,
                    organization_unit_id UUID
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (\"timestamp\")")
                .execute(pool)
                .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events (action)",
            )
            .execute(pool)
            .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_actor_user_id ON audit_events (actor_user_id)")
                .execute(pool)
                .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_case_reference ON audit_events (case_reference)")
                .execute(pool)
                .await?;

            audit::migrate_pg(pool).await?;
            mfa::migrate_pg(pool).await?;
            org::migrate_pg(pool).await?;
            biometric::migrate_pg(pool).await?;
            evidence::migrate_pg(pool).await?;
            entity_graph::migrate_pg(pool).await?;
            sqlx::query("ALTER TABLE searches ADD COLUMN IF NOT EXISTS organization_id UUID")
                .execute(pool)
                .await?;
            sqlx::query("ALTER TABLE candidates ADD COLUMN IF NOT EXISTS organization_id UUID")
                .execute(pool)
                .await?;

            seed_mock_candidates_pg(pool).await?;

            biometric::ensure_pgvector_index(pool).await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    user_code TEXT UNIQUE NOT NULL,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    national_id TEXT UNIQUE,
                    email TEXT UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'pending',
                    is_approved INTEGER NOT NULL DEFAULT 0,
                    is_banned INTEGER NOT NULL DEFAULT 0,
                    ban_reason TEXT,
                    registration_tracking_token TEXT UNIQUE,
                    registration_tracking_expires_at TEXT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                )
                "#,
            )
            .execute(pool)
            .await?;
            // Best-effort patch for a dev.db predating these columns — the
            // CREATE TABLE IF NOT EXISTS above is a no-op against an
            // existing file. Errors (column already exists) are expected
            // and ignored, same pattern as the Postgres ADD COLUMN IF NOT
            // EXISTS branch above.
            let _ = sqlx::query("ALTER TABLE users ADD COLUMN registration_tracking_token TEXT")
                .execute(pool)
                .await;
            let _ =
                sqlx::query("ALTER TABLE users ADD COLUMN registration_tracking_expires_at TEXT")
                    .execute(pool)
                    .await;
            let _ = sqlx::query("ALTER TABLE users ADD COLUMN deleted_at TEXT")
                .execute(pool)
                .await;
            let _ = sqlx::query("ALTER TABLE users ADD COLUMN national_id_encrypted TEXT")
                .execute(pool)
                .await;
            let _ = sqlx::query("ALTER TABLE users ADD COLUMN national_id_lookup_hash TEXT")
                .execute(pool)
                .await;
            sqlx::query(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_national_id_lookup_hash \
                 ON users (national_id_lookup_hash)",
            )
            .execute(pool)
            .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS candidates (
                    id TEXT PRIMARY KEY,
                    reference_code TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    notes TEXT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS searches (
                    id TEXT PRIMARY KEY,
                    case_reference TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    requested_by TEXT NOT NULL,
                    requested_by_name TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    latitude REAL,
                    longitude REAL,
                    top_k INTEGER,
                    started_at TEXT,
                    completed_at TEXT,
                    failure_code TEXT,
                    failure_message_key TEXT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                )
                "#,
            )
            .execute(pool)
            .await?;
            // Best-effort patch for a dev.db predating these columns — see
            // the equivalent Postgres ADD COLUMN IF NOT EXISTS branch above.
            let _ = sqlx::query("ALTER TABLE searches ADD COLUMN top_k INTEGER")
                .execute(pool)
                .await;
            let _ = sqlx::query("ALTER TABLE searches ADD COLUMN started_at TEXT")
                .execute(pool)
                .await;
            let _ = sqlx::query("ALTER TABLE searches ADD COLUMN completed_at TEXT")
                .execute(pool)
                .await;
            let _ = sqlx::query("ALTER TABLE searches ADD COLUMN failure_code TEXT")
                .execute(pool)
                .await;
            let _ = sqlx::query("ALTER TABLE searches ADD COLUMN failure_message_key TEXT")
                .execute(pool)
                .await;
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS search_candidates (
                    id TEXT PRIMARY KEY,
                    search_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    score REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    reviewed_by TEXT,
                    reviewed_by_name TEXT,
                    reviewed_at TEXT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_search_candidates_search_candidate \
                 ON search_candidates (search_id, candidate_id)",
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_searches_created_at ON searches (created_at)",
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_searches_case_reference ON searches (case_reference)",
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_searches_requested_by ON searches (requested_by)",
            )
            .execute(pool)
            .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS verification_events (
                    id TEXT PRIMARY KEY,
                    search_candidate_id TEXT NOT NULL,
                    reviewer_user_id TEXT NOT NULL,
                    reviewer_name TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT,
                    notes TEXT,
                    request_id TEXT,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_verification_events_search_candidate_id \
                 ON verification_events (search_candidate_id)",
            )
            .execute(pool)
            .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    refresh_token_hash TEXT NOT NULL,
                    token_family_id TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    expires_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    revoked_at TEXT,
                    user_agent TEXT,
                    ip_address TEXT,
                    rotation_counter INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)")
                .execute(pool)
                .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_token_family_id ON sessions (token_family_id)")
                .execute(pool)
                .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS approval_tokens (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT,
                    result TEXT
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_approval_tokens_user_id ON approval_tokens (user_id)")
                .execute(pool)
                .await?;

            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    actor_user_id TEXT,
                    actor_user_code TEXT,
                    actor_role TEXT,
                    action TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    case_reference TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    result TEXT NOT NULL,
                    source TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    metadata TEXT,
                    organization_id TEXT,
                    organization_unit_id TEXT
                )
                "#,
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp)",
            )
            .execute(pool)
            .await?;
            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events (action)",
            )
            .execute(pool)
            .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_actor_user_id ON audit_events (actor_user_id)")
                .execute(pool)
                .await?;
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_events_case_reference ON audit_events (case_reference)")
                .execute(pool)
                .await?;

            audit::migrate_sqlite(pool).await?;
            mfa::migrate_sqlite(pool).await?;
            org::migrate_sqlite(pool).await?;
            biometric::migrate_sqlite(pool).await?;
            evidence::migrate_sqlite(pool).await?;
            entity_graph::migrate_sqlite(pool).await?;
            let _ = sqlx::query("ALTER TABLE searches ADD COLUMN organization_id TEXT")
                .execute(pool)
                .await;
            let _ = sqlx::query("ALTER TABLE candidates ADD COLUMN organization_id TEXT")
                .execute(pool)
                .await;

            seed_mock_candidates_sqlite(pool).await?;

            false
        }
    };
    Ok(pgvector_ready)
}

/// Fictional demo records only — no real person, no real biometric data.
/// Seeded once (idempotent: only inserts when the table is empty) so the
/// mock provider has something to rank candidates against.
const MOCK_CANDIDATE_NAMES: &[&str] = &[
    "Demo Candidate Alfa",
    "Demo Candidate Bravo",
    "Demo Candidate Charlie",
    "Demo Candidate Delta",
    "Demo Candidate Echo",
    "Demo Candidate Foxtrot",
    "Demo Candidate Golf",
    "Demo Candidate Hotel",
];

async fn seed_mock_candidates_pg(pool: &PgPool) -> Result<(), sqlx::Error> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM candidates")
        .fetch_one(pool)
        .await?;
    if count > 0 {
        return Ok(());
    }
    for (i, name) in MOCK_CANDIDATE_NAMES.iter().enumerate() {
        let reference_code = format!("CAND-{:04}", i + 1);
        sqlx::query(
            "INSERT INTO candidates (reference_code, full_name, notes) VALUES ($1, $2, $3)",
        )
        .bind(&reference_code)
        .bind(name)
        .bind("Synthetic seed record for the mock biometric provider — not a real person.")
        .execute(pool)
        .await?;
    }
    Ok(())
}

async fn seed_mock_candidates_sqlite(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM candidates")
        .fetch_one(pool)
        .await?;
    if count > 0 {
        return Ok(());
    }
    for (i, name) in MOCK_CANDIDATE_NAMES.iter().enumerate() {
        let id = Uuid::new_v4().to_string();
        let reference_code = format!("CAND-{:04}", i + 1);
        sqlx::query(
            "INSERT INTO candidates (id, reference_code, full_name, notes) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&id)
        .bind(&reference_code)
        .bind(name)
        .bind("Synthetic seed record for the mock biometric provider — not a real person.")
        .execute(pool)
        .await?;
    }
    Ok(())
}

// ── Search workflow (Phase 3) ────────────────────────────────────────
//
// Postgres columns that are UUID/TIMESTAMPTZ are cast to text in every
// SELECT below (`id::text`, `created_at::text`, ...) so one shared row
// struct can `FromRow` against either backend — SQLite's columns are
// already TEXT, so the cast is a no-op there and doesn't need repeating.

#[derive(Debug, Clone, FromRow)]
pub struct CandidateRow {
    pub id: String,
    pub reference_code: String,
    pub full_name: String,
    pub notes: Option<String>,
    /// Owning organization, if any — `None` for legacy/orgless candidates
    /// (visible to anyone who passes the role check, same rule as
    /// `SearchRow::organization_id`; see `permission::can_view_scoped_resource`).
    pub organization_id: Option<String>,
}

const CANDIDATE_COLUMNS_PG: &str =
    "id::text, reference_code, full_name, notes, organization_id::text";
const CANDIDATE_COLUMNS_SQLITE: &str = "id, reference_code, full_name, notes, organization_id";

pub async fn list_candidates(backend: &DbBackend) -> Result<Vec<CandidateRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query_as::<_, CandidateRow>(&format!(
                "SELECT {CANDIDATE_COLUMNS_PG} FROM candidates ORDER BY reference_code"
            ))
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, CandidateRow>(&format!(
                "SELECT {CANDIDATE_COLUMNS_SQLITE} FROM candidates ORDER BY reference_code"
            ))
            .fetch_all(pool)
            .await
        }
    }
}

pub async fn load_candidate_by_id(
    backend: &DbBackend,
    id: &str,
) -> Result<Option<CandidateRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            sqlx::query_as::<_, CandidateRow>(&format!(
                "SELECT {CANDIDATE_COLUMNS_PG} FROM candidates WHERE id = $1"
            ))
            .bind(uuid)
            .fetch_optional(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, CandidateRow>(&format!(
                "SELECT {CANDIDATE_COLUMNS_SQLITE} FROM candidates WHERE id = ?1"
            ))
            .bind(id)
            .fetch_optional(pool)
            .await
        }
    }
}

/// Creates a new candidate record (enrollment pipeline). No
/// biometric template is attached here — that happens separately via
/// `db::biometric::insert_template` once a reference photo has been run
/// through the biometric provider's `enroll` pipeline. `organization_id`
/// stamps ownership at creation time, same pattern as
/// `create_queued_search`.
pub async fn create_candidate(
    backend: &DbBackend,
    reference_code: &str,
    full_name: &str,
    notes: Option<&str>,
    organization_id: Option<&str>,
) -> Result<CandidateRow, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let org_uuid = organization_id.and_then(|v| Uuid::parse_str(v).ok());
            sqlx::query_as::<_, CandidateRow>(&format!(
                "INSERT INTO candidates (reference_code, full_name, notes, organization_id) \
                 VALUES ($1, $2, $3, $4) \
                 RETURNING {CANDIDATE_COLUMNS_PG}"
            ))
            .bind(reference_code)
            .bind(full_name)
            .bind(notes)
            .bind(org_uuid)
            .fetch_one(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO candidates (id, reference_code, full_name, notes, organization_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&id)
            .bind(reference_code)
            .bind(full_name)
            .bind(notes)
            .bind(organization_id)
            .execute(pool)
            .await?;
            sqlx::query_as::<_, CandidateRow>(&format!(
                "SELECT {CANDIDATE_COLUMNS_SQLITE} FROM candidates WHERE id = ?1"
            ))
            .bind(&id)
            .fetch_one(pool)
            .await
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct SearchRow {
    pub id: String,
    pub case_reference: String,
    pub purpose: String,
    pub requested_by: String,
    pub requested_by_name: String,
    pub status: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    // Matches the Postgres column's actual width (`INTEGER`, 32-bit) —
    // same class of bug as `SessionRow::rotation_counter` (see
    // `db/session.rs`): sqlx's Postgres decoder rejects a struct field
    // wider than the column it reads from, which SQLite's untyped
    // storage silently tolerates. This broke both creating a search and
    // listing past ones on Postgres.
    pub top_k: Option<i32>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub failure_code: Option<String>,
    pub failure_message_key: Option<String>,
    pub created_at: String,
    /// The organization the requester belonged to at creation time, or
    /// `None` if they had no membership (see `db::org::primary_organization_id`).
    /// Never client-supplied — see `permission::can_view_scoped_resource`.
    pub organization_id: Option<String>,
}

const SEARCH_COLUMNS_PG: &str = "id::text, case_reference, purpose, requested_by::text, requested_by_name, status, \
     latitude, longitude, top_k, started_at::text, completed_at::text, failure_code, failure_message_key, created_at::text, \
     organization_id::text";
const SEARCH_COLUMNS_SQLITE: &str =
    "id, case_reference, purpose, requested_by, requested_by_name, status, latitude, \
     longitude, top_k, started_at, completed_at, failure_code, failure_message_key, created_at, organization_id";

pub async fn load_search_by_id(
    backend: &DbBackend,
    id: &str,
) -> Result<Option<SearchRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            sqlx::query_as::<_, SearchRow>(&format!(
                "SELECT {SEARCH_COLUMNS_PG} FROM searches WHERE id = $1"
            ))
            .bind(uuid)
            .fetch_optional(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, SearchRow>(&format!(
                "SELECT {SEARCH_COLUMNS_SQLITE} FROM searches WHERE id = ?1"
            ))
            .bind(id)
            .fetch_optional(pool)
            .await
        }
    }
}

const SEARCH_PAGE_MAX_SIZE: i64 = 200;

/// Server-side paginated search history, newest first. `page` is
/// 1-indexed; `page_size` is clamped to `SEARCH_PAGE_MAX_SIZE` regardless
/// of what's requested. Returns `(rows, total_matching_count)`.
///
/// `org_scope` implements object-level authorization at the
/// query level rather than post-filtering a page after the fact, which
/// would silently short a page instead of returning a full one. `None`
/// means unscoped (only `SYSTEM_ADMIN` passes this) — every search is
/// visible. `Some(ids)` restricts results to searches owned by one of
/// `ids`, or with no owning organization at all (legacy/unassigned data
/// stays visible to everyone with the underlying role permission, rather
/// than becoming invisible the moment the org model is introduced).
pub async fn list_searches_page(
    backend: &DbBackend,
    page: i64,
    page_size: i64,
    org_scope: Option<&[String]>,
) -> Result<(Vec<SearchRow>, i64), sqlx::Error> {
    let page = page.max(1);
    let page_size = page_size.clamp(1, SEARCH_PAGE_MAX_SIZE);
    let offset = (page - 1) * page_size;
    match backend {
        DbBackend::Postgres(pool) => {
            let mut count_builder =
                sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT COUNT(*) FROM searches");
            push_search_org_scope_pg(&mut count_builder, org_scope);
            let total: i64 = count_builder.build_query_scalar().fetch_one(pool).await?;

            let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
                "SELECT {SEARCH_COLUMNS_PG} FROM searches"
            ));
            push_search_org_scope_pg(&mut builder, org_scope);
            builder.push(" ORDER BY created_at DESC LIMIT ");
            builder.push_bind(page_size);
            builder.push(" OFFSET ");
            builder.push_bind(offset);
            let rows = builder
                .build_query_as::<SearchRow>()
                .fetch_all(pool)
                .await?;
            Ok((rows, total))
        }
        DbBackend::Sqlite(pool) => {
            let mut count_builder =
                sqlx::QueryBuilder::<sqlx::Sqlite>::new("SELECT COUNT(*) FROM searches");
            push_search_org_scope_sqlite(&mut count_builder, org_scope);
            let total: i64 = count_builder.build_query_scalar().fetch_one(pool).await?;

            let mut builder = sqlx::QueryBuilder::<sqlx::Sqlite>::new(format!(
                "SELECT {SEARCH_COLUMNS_SQLITE} FROM searches"
            ));
            push_search_org_scope_sqlite(&mut builder, org_scope);
            builder.push(" ORDER BY created_at DESC LIMIT ");
            builder.push_bind(page_size);
            builder.push(" OFFSET ");
            builder.push_bind(offset);
            let rows = builder
                .build_query_as::<SearchRow>()
                .fetch_all(pool)
                .await?;
            Ok((rows, total))
        }
    }
}

fn push_search_org_scope_pg<'a>(
    builder: &mut sqlx::QueryBuilder<'a, sqlx::Postgres>,
    org_scope: Option<&'a [String]>,
) {
    let Some(ids) = org_scope else { return };
    let uuids: Vec<Uuid> = ids.iter().filter_map(|v| Uuid::parse_str(v).ok()).collect();
    builder.push(" WHERE (organization_id IS NULL OR organization_id = ANY(");
    builder.push_bind(uuids);
    builder.push("))");
}

fn push_search_org_scope_sqlite<'a>(
    builder: &mut sqlx::QueryBuilder<'a, sqlx::Sqlite>,
    org_scope: Option<&'a [String]>,
) {
    let Some(ids) = org_scope else { return };
    if ids.is_empty() {
        builder.push(" WHERE organization_id IS NULL");
        return;
    }
    builder.push(" WHERE (organization_id IS NULL OR organization_id IN (");
    let mut separated = builder.separated(", ");
    for id in ids {
        separated.push_bind(id.clone());
    }
    separated.push_unseparated(")");
    builder.push(")");
}

/// Creates a search row in `queued` status with no candidates yet —
/// the fast, synchronous half of the async search flow:
/// `POST /api/v1/search/face` inserts this row and returns `202 Accepted`
/// with its id immediately, before the (potentially slow) biometric
/// pipeline has even started. `started_at` is left unset until
/// `finalize_queued_search` actually begins processing.
#[allow(clippy::too_many_arguments)]
pub async fn create_queued_search(
    backend: &DbBackend,
    case_reference: &str,
    purpose: &str,
    requested_by: &str,
    requested_by_name: &str,
    latitude: Option<f64>,
    longitude: Option<f64>,
    top_k: i64,
    organization_id: Option<&str>,
) -> Result<SearchRow, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let requester_uuid = Uuid::parse_str(requested_by)
                .map_err(|e| sqlx::Error::Protocol(format!("invalid requested_by uuid: {e}")))?;
            let org_uuid = organization_id.and_then(|v| Uuid::parse_str(v).ok());
            sqlx::query_as(&format!(
                "INSERT INTO searches (case_reference, purpose, requested_by, requested_by_name, latitude, longitude,
                 top_k, status, organization_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'queued', $8) RETURNING {SEARCH_COLUMNS_PG}"
            ))
            .bind(case_reference)
            .bind(purpose)
            .bind(requester_uuid)
            .bind(requested_by_name)
            .bind(latitude)
            .bind(longitude)
            .bind(top_k)
            .bind(org_uuid)
            .fetch_one(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO searches (id, case_reference, purpose, requested_by, requested_by_name, latitude, longitude,
                 top_k, status, organization_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9)",
            )
            .bind(&id)
            .bind(case_reference)
            .bind(purpose)
            .bind(requested_by)
            .bind(requested_by_name)
            .bind(latitude)
            .bind(longitude)
            .bind(top_k)
            .bind(organization_id)
            .execute(pool)
            .await?;
            sqlx::query_as(&format!(
                "SELECT {SEARCH_COLUMNS_SQLITE} FROM searches WHERE id = ?1"
            ))
            .bind(&id)
            .fetch_one(pool)
            .await
        }
    }
}

/// The background half of the async search flow: marks a previously
/// `queued` search `processing`, writes every candidate result, then
/// marks it `completed` — all in one transaction, so a failure partway
/// through never leaves a partial candidate list visible.
pub async fn finalize_queued_search(
    backend: &DbBackend,
    search_id: &str,
    scored: &[(String, f64)],
) -> Result<Option<SearchRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(search_uuid) = Uuid::parse_str(search_id) else {
                return Ok(None);
            };
            let mut tx = pool.begin().await?;
            sqlx::query(
                "UPDATE searches SET status = 'processing', started_at = NOW() WHERE id = $1",
            )
            .bind(search_uuid)
            .execute(&mut *tx)
            .await?;
            for (candidate_id, score) in scored {
                let Ok(candidate_uuid) = Uuid::parse_str(candidate_id) else {
                    continue;
                };
                sqlx::query("INSERT INTO search_candidates (search_id, candidate_id, score) VALUES ($1, $2, $3)")
                    .bind(search_uuid)
                    .bind(candidate_uuid)
                    .bind(score)
                    .execute(&mut *tx)
                    .await?;
            }
            let completed: SearchRow = sqlx::query_as(&format!(
                "UPDATE searches SET status = 'completed', completed_at = NOW() WHERE id = $1 RETURNING {SEARCH_COLUMNS_PG}"
            ))
            .bind(search_uuid)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(Some(completed))
        }
        DbBackend::Sqlite(pool) => {
            let mut tx = pool.begin().await?;
            sqlx::query(
                "UPDATE searches SET status = 'processing', started_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1",
            )
            .bind(search_id)
            .execute(&mut *tx)
            .await?;
            for (candidate_id, score) in scored {
                let row_id = Uuid::new_v4().to_string();
                sqlx::query("INSERT INTO search_candidates (id, search_id, candidate_id, score) VALUES (?1, ?2, ?3, ?4)")
                    .bind(&row_id)
                    .bind(search_id)
                    .bind(candidate_id)
                    .bind(score)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query(
                "UPDATE searches SET status = 'completed', completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1",
            )
            .bind(search_id)
            .execute(&mut *tx)
            .await?;
            let completed = sqlx::query_as(&format!(
                "SELECT {SEARCH_COLUMNS_SQLITE} FROM searches WHERE id = ?1"
            ))
            .bind(search_id)
            .fetch_optional(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(completed)
        }
    }
}

/// Marks a previously `queued`/`processing` search `failed` — used both
/// when the biometric provider rejects the probe and when finalization
/// itself fails partway through.
pub async fn mark_queued_search_failed(
    backend: &DbBackend,
    search_id: &str,
    failure_code: &str,
    failure_message_key: &str,
) -> Result<Option<SearchRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(search_uuid) = Uuid::parse_str(search_id) else {
                return Ok(None);
            };
            sqlx::query_as(&format!(
                "UPDATE searches SET status = 'failed', completed_at = NOW(), failure_code = $2, \
                 failure_message_key = $3 WHERE id = $1 RETURNING {SEARCH_COLUMNS_PG}"
            ))
            .bind(search_uuid)
            .bind(failure_code)
            .bind(failure_message_key)
            .fetch_optional(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "UPDATE searches SET status = 'failed', completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), \
                 failure_code = ?2, failure_message_key = ?3 WHERE id = ?1",
            )
            .bind(search_id)
            .bind(failure_code)
            .bind(failure_message_key)
            .execute(pool)
            .await?;
            sqlx::query_as(&format!(
                "SELECT {SEARCH_COLUMNS_SQLITE} FROM searches WHERE id = ?1"
            ))
            .bind(search_id)
            .fetch_optional(pool)
            .await
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct SearchCandidateRow {
    pub id: String,
    pub search_id: String,
    pub candidate_id: String,
    pub candidate_reference_code: String,
    pub candidate_full_name: String,
    pub score: f64,
    pub status: String,
    pub reviewed_by: Option<String>,
    pub reviewed_by_name: Option<String>,
    pub reviewed_at: Option<String>,
    pub created_at: String,
}

const SEARCH_CANDIDATE_SELECT_PG: &str = r#"
    SELECT sc.id::text, sc.search_id::text, sc.candidate_id::text,
           c.reference_code AS candidate_reference_code, c.full_name AS candidate_full_name,
           sc.score, sc.status, sc.reviewed_by::text AS reviewed_by, sc.reviewed_by_name,
           sc.reviewed_at::text AS reviewed_at, sc.created_at::text
    FROM search_candidates sc
    JOIN candidates c ON c.id = sc.candidate_id
"#;

const SEARCH_CANDIDATE_SELECT_SQLITE: &str = r#"
    SELECT sc.id, sc.search_id, sc.candidate_id,
           c.reference_code AS candidate_reference_code, c.full_name AS candidate_full_name,
           sc.score, sc.status, sc.reviewed_by, sc.reviewed_by_name,
           sc.reviewed_at, sc.created_at
    FROM search_candidates sc
    JOIN candidates c ON c.id = sc.candidate_id
"#;

pub async fn insert_search_candidate(
    backend: &DbBackend,
    search_id: &str,
    candidate_id: &str,
    score: f64,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let (Ok(search_uuid), Ok(candidate_uuid)) =
                (Uuid::parse_str(search_id), Uuid::parse_str(candidate_id))
            else {
                return Ok(());
            };
            sqlx::query("INSERT INTO search_candidates (search_id, candidate_id, score) VALUES ($1, $2, $3)")
                .bind(search_uuid)
                .bind(candidate_uuid)
                .bind(score)
                .execute(pool)
                .await?;
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query("INSERT INTO search_candidates (id, search_id, candidate_id, score) VALUES (?1, ?2, ?3, ?4)")
                .bind(&id)
                .bind(search_id)
                .bind(candidate_id)
                .bind(score)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

pub async fn list_search_candidates(
    backend: &DbBackend,
    search_id: &str,
) -> Result<Vec<SearchCandidateRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(search_id) else {
                return Ok(vec![]);
            };
            sqlx::query_as::<_, SearchCandidateRow>(&format!(
                "{SEARCH_CANDIDATE_SELECT_PG} WHERE sc.search_id = $1 ORDER BY sc.score DESC"
            ))
            .bind(uuid)
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, SearchCandidateRow>(&format!(
                "{SEARCH_CANDIDATE_SELECT_SQLITE} WHERE sc.search_id = ?1 ORDER BY sc.score DESC"
            ))
            .bind(search_id)
            .fetch_all(pool)
            .await
        }
    }
}

/// Outcome of `record_review_decision`. Distinguishes "nothing to review"
/// from the four-eyes-specific refusal so callers can return the right
/// HTTP status for each.
pub enum ReviewDecisionOutcome {
    Applied(Box<SearchCandidateRow>),
    NotFound,
    /// Four-eyes is enabled and this candidate is `needs_second_review`,
    /// but the reviewer submitting now is the same one who made the first
    /// decision — a second, *different* reviewer must finalize it.
    SameReviewerForbidden,
}

/// Sets a candidate's review status (`confirmed`/`rejected`) within one
/// search. This is the one explicit human verification action that sets
/// "Confirmed Identity" — never derived automatically from a score.
/// Records one review decision: inserts an immutable `verification_events`
/// row (never overwritten or deleted — see docs/SECURITY_ARCHITECTURE.md)
/// and updates `search_candidates`'s current-status columns, atomically.
/// A later decision on the same candidate adds another event row rather
/// than replacing this one; `search_candidates.status`/`reviewed_*` only
/// ever reflect the most recent decision, the full history lives in
/// `verification_events`.
///
/// When `require_second_review` is `true` (four-eyes review), a
/// `confirmed`/`rejected` decision on a candidate that isn't already
/// `needs_second_review` only ever moves it *to* `needs_second_review` —
/// it never finalizes a candidate by itself. A second, different
/// reviewer's subsequent `confirmed`/`rejected` decision on that same
/// `needs_second_review` candidate is what finalizes it, to whatever that
/// second reviewer decided (Reviewer B has final say, per the
/// instructions' own "Reviewer A → First Review, Reviewer B → Final
/// Review" model). The same reviewer cannot supply both the first and
/// the final decision — see `ReviewDecisionOutcome::SameReviewerForbidden`.
/// `inconclusive` decisions bypass this entirely; they never finalize
/// anything regardless of `require_second_review`.
#[allow(clippy::too_many_arguments)]
pub async fn record_review_decision(
    backend: &DbBackend,
    search_id: &str,
    candidate_id: &str,
    decision: &str,
    reviewed_by: &str,
    reviewed_by_name: &str,
    reason: Option<&str>,
    notes: Option<&str>,
    request_id: &str,
    require_second_review: bool,
) -> Result<ReviewDecisionOutcome, sqlx::Error> {
    let is_finalizing_decision = decision == "confirmed" || decision == "rejected";
    match backend {
        DbBackend::Postgres(pool) => {
            let (Ok(search_uuid), Ok(candidate_uuid), Ok(reviewer_uuid)) = (
                Uuid::parse_str(search_id),
                Uuid::parse_str(candidate_id),
                Uuid::parse_str(reviewed_by),
            ) else {
                return Ok(ReviewDecisionOutcome::NotFound);
            };
            let mut tx = pool.begin().await?;
            let current: Option<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
                "SELECT id, status, reviewed_by FROM search_candidates \
                 WHERE search_id = $1 AND candidate_id = $2 FOR UPDATE",
            )
            .bind(search_uuid)
            .bind(candidate_uuid)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((search_candidate_id, current_status, current_reviewed_by)) = current else {
                return Ok(ReviewDecisionOutcome::NotFound);
            };

            let target_status = if !require_second_review || !is_finalizing_decision {
                decision.to_string()
            } else if current_status == "needs_second_review" {
                if current_reviewed_by == Some(reviewer_uuid) {
                    return Ok(ReviewDecisionOutcome::SameReviewerForbidden);
                }
                decision.to_string()
            } else {
                "needs_second_review".to_string()
            };

            sqlx::query(
                "INSERT INTO verification_events
                 (search_candidate_id, reviewer_user_id, reviewer_name, decision, reason, notes, request_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(search_candidate_id)
            .bind(reviewer_uuid)
            .bind(reviewed_by_name)
            .bind(decision)
            .bind(reason)
            .bind(notes)
            .bind(request_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE search_candidates SET status = $1, reviewed_by = $2, reviewed_by_name = $3, reviewed_at = NOW()
                 WHERE id = $4",
            )
            .bind(&target_status)
            .bind(reviewer_uuid)
            .bind(reviewed_by_name)
            .bind(search_candidate_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }
        DbBackend::Sqlite(pool) => {
            let mut tx = pool.begin().await?;
            let current: Option<(String, String, Option<String>)> = sqlx::query_as(
                "SELECT id, status, reviewed_by FROM search_candidates \
                 WHERE search_id = ?1 AND candidate_id = ?2",
            )
            .bind(search_id)
            .bind(candidate_id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((search_candidate_id, current_status, current_reviewed_by)) = current else {
                return Ok(ReviewDecisionOutcome::NotFound);
            };

            let target_status = if !require_second_review || !is_finalizing_decision {
                decision.to_string()
            } else if current_status == "needs_second_review" {
                if current_reviewed_by.as_deref() == Some(reviewed_by) {
                    return Ok(ReviewDecisionOutcome::SameReviewerForbidden);
                }
                decision.to_string()
            } else {
                "needs_second_review".to_string()
            };

            let event_id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO verification_events
                 (id, search_candidate_id, reviewer_user_id, reviewer_name, decision, reason, notes, request_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(&event_id)
            .bind(&search_candidate_id)
            .bind(reviewed_by)
            .bind(reviewed_by_name)
            .bind(decision)
            .bind(reason)
            .bind(notes)
            .bind(request_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE search_candidates SET status = ?1, reviewed_by = ?2, reviewed_by_name = ?3,
                 reviewed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?4",
            )
            .bind(&target_status)
            .bind(reviewed_by)
            .bind(reviewed_by_name)
            .bind(&search_candidate_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }
    }
    let rows = list_search_candidates(backend, search_id).await?;
    Ok(
        match rows
            .into_iter()
            .find(|row| row.candidate_id == candidate_id)
        {
            Some(row) => ReviewDecisionOutcome::Applied(Box::new(row)),
            None => ReviewDecisionOutcome::NotFound,
        },
    )
}

#[derive(Debug, Clone, FromRow)]
pub struct VerificationEventRow {
    pub id: String,
    pub search_candidate_id: String,
    pub reviewer_user_id: String,
    pub reviewer_name: String,
    pub decision: String,
    pub reason: Option<String>,
    pub notes: Option<String>,
    pub request_id: Option<String>,
    pub created_at: String,
}

const VERIFICATION_EVENT_COLUMNS_PG: &str =
    "id::text, search_candidate_id::text, reviewer_user_id::text, \
     reviewer_name, decision, reason, notes, request_id, created_at::text";
const VERIFICATION_EVENT_COLUMNS_SQLITE: &str =
    "id, search_candidate_id, reviewer_user_id, reviewer_name, decision, reason, notes, request_id, created_at";

/// Full, unabridged review history for one candidate within one search —
/// every decision ever recorded, oldest first, never just the latest one.
pub async fn list_verification_events(
    backend: &DbBackend,
    search_candidate_id: &str,
) -> Result<Vec<VerificationEventRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(search_candidate_id) else {
                return Ok(vec![]);
            };
            sqlx::query_as::<_, VerificationEventRow>(&format!(
                "SELECT {VERIFICATION_EVENT_COLUMNS_PG} FROM verification_events \
                 WHERE search_candidate_id = $1 ORDER BY created_at ASC"
            ))
            .bind(uuid)
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, VerificationEventRow>(&format!(
                "SELECT {VERIFICATION_EVENT_COLUMNS_SQLITE} FROM verification_events \
                 WHERE search_candidate_id = ?1 ORDER BY created_at ASC"
            ))
            .bind(search_candidate_id)
            .fetch_all(pool)
            .await
        }
    }
}
