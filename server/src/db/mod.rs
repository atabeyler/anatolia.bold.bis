use std::sync::Arc;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool, SqlitePool};
use std::str::FromStr;
use uuid::Uuid;

use crate::config::Config;
use crate::ratelimit::{InMemoryRateLimiter, RateLimiterBackend};

// Domain modules. Each groups the tables/queries for one area of the
// system (see docs/HARDENING_CHECKLIST.md item 31); everything else in
// this file is shared infrastructure (connection setup, schema
// migration, `AppState`) that every domain depends on rather than
// belonging to one of them. Re-exported so existing call sites
// (`crate::db::AuditEventRow`, etc.) don't need to change.
mod audit;
pub use audit::*;
mod mfa;
pub use mfa::*;
mod org;
pub use org::*;

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
        migrate(&backend).await?;
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
        }
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

async fn migrate(backend: &DbBackend) -> Result<(), sqlx::Error> {
    match backend {
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
                    score REAL NOT NULL,
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
            // than one relying solely on `create_search_with_candidates`
            // never inserting a duplicate. `search` history/filtering reads
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
            sqlx::query("ALTER TABLE searches ADD COLUMN IF NOT EXISTS organization_id UUID")
                .execute(pool)
                .await?;
            sqlx::query("ALTER TABLE candidates ADD COLUMN IF NOT EXISTS organization_id UUID")
                .execute(pool)
                .await?;

            seed_mock_candidates_pg(pool).await?;
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
            let _ = sqlx::query("ALTER TABLE searches ADD COLUMN organization_id TEXT")
                .execute(pool)
                .await;
            let _ = sqlx::query("ALTER TABLE candidates ADD COLUMN organization_id TEXT")
                .execute(pool)
                .await;

            seed_mock_candidates_sqlite(pool).await?;
        }
    }
    Ok(())
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

#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: String,
    pub user_code: String,
    pub first_name: String,
    pub last_name: String,
    /// AES-256-GCM ciphertext (base64) — see `national_id.rs`. Never the
    /// plaintext national ID; decrypt only where genuinely needed (today:
    /// solely to mask it for display, see `admin::mask_national_id`).
    pub national_id_encrypted: Option<String>,
    /// Deterministic HMAC-SHA256 of the plaintext — carries the
    /// duplicate-detection uniqueness that used to sit on a plaintext
    /// `UNIQUE` column.
    pub national_id_lookup_hash: Option<String>,
    pub email: Option<String>,
    pub password_hash: String,
    pub role: String,
    pub is_approved: bool,
    pub is_banned: bool,
    pub ban_reason: Option<String>,
}

#[derive(sqlx::FromRow)]
struct PgUserRow {
    id: Uuid,
    user_code: String,
    first_name: String,
    last_name: String,
    national_id_encrypted: Option<String>,
    national_id_lookup_hash: Option<String>,
    email: Option<String>,
    password_hash: String,
    role: String,
    is_approved: bool,
    is_banned: bool,
    ban_reason: Option<String>,
}

impl From<PgUserRow> for UserRow {
    fn from(row: PgUserRow) -> Self {
        Self {
            id: row.id.to_string(),
            user_code: row.user_code,
            first_name: row.first_name,
            last_name: row.last_name,
            national_id_encrypted: row.national_id_encrypted,
            national_id_lookup_hash: row.national_id_lookup_hash,
            email: row.email,
            password_hash: row.password_hash,
            role: row.role,
            is_approved: row.is_approved,
            is_banned: row.is_banned,
            ban_reason: row.ban_reason,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SqliteUserRow {
    id: String,
    user_code: String,
    first_name: String,
    last_name: String,
    national_id_encrypted: Option<String>,
    national_id_lookup_hash: Option<String>,
    email: Option<String>,
    password_hash: String,
    role: String,
    is_approved: i64,
    is_banned: i64,
    ban_reason: Option<String>,
}

impl From<SqliteUserRow> for UserRow {
    fn from(row: SqliteUserRow) -> Self {
        Self {
            id: row.id,
            user_code: row.user_code,
            first_name: row.first_name,
            last_name: row.last_name,
            national_id_encrypted: row.national_id_encrypted,
            national_id_lookup_hash: row.national_id_lookup_hash,
            email: row.email,
            password_hash: row.password_hash,
            role: row.role,
            is_approved: row.is_approved != 0,
            is_banned: row.is_banned != 0,
            ban_reason: row.ban_reason,
        }
    }
}

const USER_COLUMNS: &str = "id, user_code, first_name, last_name, national_id_encrypted, \
     national_id_lookup_hash, email, password_hash, role, is_approved, is_banned, ban_reason";

pub async fn load_user_by_code(
    backend: &DbBackend,
    user_code: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    let code = user_code.trim().to_uppercase();
    match backend {
        DbBackend::Postgres(pool) => {
            let row = sqlx::query_as::<_, PgUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE user_code = $1 AND deleted_at IS NULL"
            ))
            .bind(&code)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(UserRow::from))
        }
        DbBackend::Sqlite(pool) => {
            let row = sqlx::query_as::<_, SqliteUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE user_code = ?1 AND deleted_at IS NULL"
            ))
            .bind(&code)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(UserRow::from))
        }
    }
}

/// Excludes soft-deleted accounts (`deleted_at IS NOT NULL`) — used
/// everywhere a deleted account must behave as if it no longer exists
/// (login, session/token validation, admin listing/editing). The row
/// itself is kept, not physically removed, so `search`/`audit_events`/
/// `verification_events` rows that reference this user's id as an actor
/// stay resolvable.
pub async fn load_user_by_id(
    backend: &DbBackend,
    id: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            let row = sqlx::query_as::<_, PgUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE id = $1 AND deleted_at IS NULL"
            ))
            .bind(uuid)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(UserRow::from))
        }
        DbBackend::Sqlite(pool) => {
            let row = sqlx::query_as::<_, SqliteUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE id = ?1 AND deleted_at IS NULL"
            ))
            .bind(id)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(UserRow::from))
        }
    }
}

/// Counts non-banned `SYSTEM_ADMIN` accounts — used to refuse an action
/// (ban/delete) that would leave the platform with zero administrators
/// able to sign in and undo it.
pub async fn count_active_system_admins(backend: &DbBackend) -> Result<i64, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let (count,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM users WHERE role = $1 AND is_banned = false AND deleted_at IS NULL",
            )
            .bind(crate::roles::SYSTEM_ADMIN)
            .fetch_one(pool)
            .await?;
            Ok(count)
        }
        DbBackend::Sqlite(pool) => {
            let (count,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM users WHERE role = ?1 AND is_banned = 0 AND deleted_at IS NULL",
            )
            .bind(crate::roles::SYSTEM_ADMIN)
            .fetch_one(pool)
            .await?;
            Ok(count)
        }
    }
}

pub async fn list_users(backend: &DbBackend) -> Result<Vec<UserRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let rows = sqlx::query_as::<_, PgUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC"
            ))
            .fetch_all(pool)
            .await?;
            Ok(rows.into_iter().map(UserRow::from).collect())
        }
        DbBackend::Sqlite(pool) => {
            let rows = sqlx::query_as::<_, SqliteUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC"
            ))
            .fetch_all(pool)
            .await?;
            Ok(rows.into_iter().map(UserRow::from).collect())
        }
    }
}

const USER_PAGE_MAX_SIZE: i64 = 200;

/// Server-side paginated variant of `list_users` — see item 30 in
/// `docs/HARDENING_CHECKLIST.md`. `list_users` (unpaged) is kept for
/// callers (e.g. `count_active_system_admins`-adjacent internal checks)
/// that genuinely need every row; `GET /api/v1/admin/users` uses this one.
pub async fn list_users_page(
    backend: &DbBackend,
    page: i64,
    page_size: i64,
) -> Result<(Vec<UserRow>, i64), sqlx::Error> {
    let page = page.max(1);
    let page_size = page_size.clamp(1, USER_PAGE_MAX_SIZE);
    let offset = (page - 1) * page_size;
    match backend {
        DbBackend::Postgres(pool) => {
            let total: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
                    .fetch_one(pool)
                    .await?;
            let rows = sqlx::query_as::<_, PgUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2"
            ))
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;
            Ok((rows.into_iter().map(UserRow::from).collect(), total))
        }
        DbBackend::Sqlite(pool) => {
            let total: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
                    .fetch_one(pool)
                    .await?;
            let rows = sqlx::query_as::<_, SqliteUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
            ))
            .bind(page_size)
            .bind(offset)
            .fetch_all(pool)
            .await?;
            Ok((rows.into_iter().map(UserRow::from).collect(), total))
        }
    }
}

/// Creates a new user with `role` and, unless `is_approved` is passed as
/// `true` (only used by admin seeding), leaves it pending admin review.
#[allow(clippy::too_many_arguments)]
pub async fn create_user(
    backend: &DbBackend,
    user_code: &str,
    email: Option<&str>,
    first_name: &str,
    last_name: &str,
    national_id_encrypted: Option<&str>,
    national_id_lookup_hash: Option<&str>,
    password_hash: &str,
    role: &str,
    is_approved: bool,
) -> Result<Option<UserRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let row = sqlx::query_as::<_, PgUserRow>(&format!(
                "INSERT INTO users (user_code, email, first_name, last_name, national_id_encrypted, national_id_lookup_hash, password_hash, role, is_approved)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                 RETURNING {USER_COLUMNS}"
            ))
            .bind(user_code)
            .bind(email)
            .bind(first_name)
            .bind(last_name)
            .bind(national_id_encrypted)
            .bind(national_id_lookup_hash)
            .bind(password_hash)
            .bind(role)
            .bind(is_approved)
            .fetch_one(pool)
            .await?;
            Ok(Some(UserRow::from(row)))
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO users (id, user_code, email, first_name, last_name, national_id_encrypted, national_id_lookup_hash, password_hash, role, is_approved)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )
            .bind(&id)
            .bind(user_code)
            .bind(email)
            .bind(first_name)
            .bind(last_name)
            .bind(national_id_encrypted)
            .bind(national_id_lookup_hash)
            .bind(password_hash)
            .bind(role)
            .bind(is_approved as i64)
            .execute(pool)
            .await?;
            load_user_by_id(backend, &id).await
        }
    }
}

/// Stores the unguessable pointer a pending applicant polls with instead
/// of their own (guessable) user code — see `auth::registration_status`.
pub async fn set_registration_tracking_token(
    backend: &DbBackend,
    user_id: &str,
    token: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(user_id) else {
                return Ok(());
            };
            sqlx::query("UPDATE users SET registration_tracking_token = $1, registration_tracking_expires_at = $2 WHERE id = $3")
                .bind(token)
                .bind(expires_at)
                .bind(uuid)
                .execute(pool)
                .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query("UPDATE users SET registration_tracking_token = ?1, registration_tracking_expires_at = ?2 WHERE id = ?3")
                .bind(token)
                .bind(expires_at.to_rfc3339())
                .bind(user_id)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

pub struct RegistrationTrackingStatus {
    pub is_approved: bool,
    pub is_banned: bool,
    pub expires_at: String,
}

/// Looks a pending registration's status up by its unguessable tracking
/// token instead of the (guessable, four-to-twenty-character) user code —
/// the enumeration protection `auth::registration_status` relies on.
pub async fn load_registration_tracking_status(
    backend: &DbBackend,
    token: &str,
) -> Result<Option<RegistrationTrackingStatus>, sqlx::Error> {
    use sqlx::Row;
    match backend {
        DbBackend::Postgres(pool) => {
            let row = sqlx::query(
                "SELECT is_approved, is_banned, registration_tracking_expires_at::text AS expires_at \
                 FROM users WHERE registration_tracking_token = $1",
            )
            .bind(token)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(|r| RegistrationTrackingStatus {
                is_approved: r.try_get("is_approved").unwrap_or(false),
                is_banned: r.try_get("is_banned").unwrap_or(false),
                expires_at: r
                    .try_get::<Option<String>, _>("expires_at")
                    .ok()
                    .flatten()
                    .unwrap_or_default(),
            }))
        }
        DbBackend::Sqlite(pool) => {
            let row = sqlx::query(
                "SELECT is_approved, is_banned, registration_tracking_expires_at AS expires_at \
                 FROM users WHERE registration_tracking_token = ?1",
            )
            .bind(token)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(|r| RegistrationTrackingStatus {
                is_approved: r
                    .try_get::<i64, _>("is_approved")
                    .map(|v| v != 0)
                    .unwrap_or(false),
                is_banned: r
                    .try_get::<i64, _>("is_banned")
                    .map(|v| v != 0)
                    .unwrap_or(false),
                expires_at: r
                    .try_get::<Option<String>, _>("expires_at")
                    .ok()
                    .flatten()
                    .unwrap_or_default(),
            }))
        }
    }
}

/// Sets any subset of the moderation flags on a user; pass `None` to leave
/// a field unchanged. Returns the updated row, or `None` if no user with
/// this id exists.
pub async fn update_user_flags(
    backend: &DbBackend,
    id: &str,
    is_approved: Option<bool>,
    is_banned: Option<bool>,
    ban_reason: Option<&str>,
    role: Option<&str>,
) -> Result<Option<UserRow>, sqlx::Error> {
    let Some(current) = load_user_by_id(backend, id).await? else {
        return Ok(None);
    };
    let next_approved = is_approved.unwrap_or(current.is_approved);
    let next_banned = is_banned.unwrap_or(current.is_banned);
    let next_ban_reason = ban_reason.map(str::to_string).or(current.ban_reason);
    let next_role = role.unwrap_or(&current.role).to_string();

    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            sqlx::query(
                "UPDATE users SET is_approved = $1, is_banned = $2, ban_reason = $3, role = $4, updated_at = NOW() WHERE id = $5",
            )
            .bind(next_approved)
            .bind(next_banned)
            .bind(&next_ban_reason)
            .bind(&next_role)
            .bind(uuid)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "UPDATE users SET is_approved = ?1, is_banned = ?2, ban_reason = ?3, role = ?4, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?5",
            )
            .bind(next_approved as i64)
            .bind(next_banned as i64)
            .bind(&next_ban_reason)
            .bind(&next_role)
            .bind(id)
            .execute(pool)
            .await?;
        }
    }
    load_user_by_id(backend, id).await
}

/// Admin-driven profile edit (nickname/national ID/email/password reset).
/// Distinct from `update_user_flags`: that one governs moderation state
/// (approval/ban/role), this one governs the account's own identifying
/// details.
#[allow(clippy::too_many_arguments)]
pub async fn update_user_profile(
    backend: &DbBackend,
    id: &str,
    first_name: &str,
    email: Option<&str>,
    national_id_encrypted: Option<&str>,
    national_id_lookup_hash: Option<&str>,
    password_hash: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            sqlx::query(
                "UPDATE users SET first_name = $1, email = $2, national_id_encrypted = $3, national_id_lookup_hash = $4, password_hash = $5, updated_at = NOW() WHERE id = $6",
            )
            .bind(first_name)
            .bind(email)
            .bind(national_id_encrypted)
            .bind(national_id_lookup_hash)
            .bind(password_hash)
            .bind(uuid)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "UPDATE users SET first_name = ?1, email = ?2, national_id_encrypted = ?3, national_id_lookup_hash = ?4, password_hash = ?5, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?6",
            )
            .bind(first_name)
            .bind(email)
            .bind(national_id_encrypted)
            .bind(national_id_lookup_hash)
            .bind(password_hash)
            .bind(id)
            .execute(pool)
            .await?;
        }
    }
    load_user_by_id(backend, id).await
}

/// Sets a user's password hash only — used by the self-service password
/// reset flow (`auth::reset_password`), distinct from `update_user_profile`
/// (an admin editing an account's identifying details).
pub async fn update_user_password(
    backend: &DbBackend,
    id: &str,
    password_hash: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
                .bind(password_hash)
                .bind(uuid)
                .execute(pool)
                .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "UPDATE users SET password_hash = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?2",
            )
            .bind(password_hash)
            .bind(id)
            .execute(pool)
            .await?;
        }
    }
    load_user_by_id(backend, id).await
}

pub async fn load_user_by_email(
    backend: &DbBackend,
    email: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    let email = email.trim().to_lowercase();
    match backend {
        DbBackend::Postgres(pool) => {
            let row = sqlx::query_as::<_, PgUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE email = $1 AND deleted_at IS NULL"
            ))
            .bind(&email)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(UserRow::from))
        }
        DbBackend::Sqlite(pool) => {
            let row = sqlx::query_as::<_, SqliteUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE email = ?1 AND deleted_at IS NULL"
            ))
            .bind(&email)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(UserRow::from))
        }
    }
}

/// Hard delete — physically removes the row. Only appropriate for a
/// pending registration that was never approved (`admin::reject_user`,
/// `admin::quick_reject`): nothing else in the database can reference that
/// user's id yet, so there is no history to orphan. An admin removing an
/// established account uses `soft_delete_user` instead.
pub async fn delete_user(backend: &DbBackend, id: &str) -> Result<bool, sqlx::Error> {
    let affected = match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(false);
            };
            sqlx::query("DELETE FROM users WHERE id = $1")
                .bind(uuid)
                .execute(pool)
                .await?
                .rows_affected()
        }
        DbBackend::Sqlite(pool) => sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected(),
    };
    Ok(affected > 0)
}

/// Marks an established account as deleted without removing the row —
/// `searches.requested_by`, `verification_events.reviewer_user_id`, and
/// `audit_events.actor_user_id` can all reference this user's id, and a
/// hard delete would leave those pointing at nothing. Every read that
/// should treat the account as gone (login, session/token validation,
/// admin listing) filters on `deleted_at IS NULL`, so a soft-deleted user
/// behaves as fully removed from every angle that matters, while its past
/// actions remain attributable. Idempotent: deleting an already-deleted
/// user is a no-op that still reports success, matching `delete_user`'s
/// idempotent-looking shape (`Ok(false)` only for a truly nonexistent id).
pub async fn soft_delete_user(backend: &DbBackend, id: &str) -> Result<bool, sqlx::Error> {
    let affected = match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(false);
            };
            sqlx::query("UPDATE users SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL")
                .bind(uuid)
                .execute(pool)
                .await?
                .rows_affected()
        }
        DbBackend::Sqlite(pool) => sqlx::query(
            "UPDATE users SET deleted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ?1 AND deleted_at IS NULL",
        )
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected(),
    };
    if affected > 0 {
        return Ok(true);
    }
    // Either the id doesn't exist at all, or it was already deleted —
    // distinguish the two so the route can still return 404 for a
    // genuinely unknown id.
    Ok(load_user_by_id_including_deleted(backend, id)
        .await?
        .is_some())
}

async fn load_user_by_id_including_deleted(
    backend: &DbBackend,
    id: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            let row = sqlx::query_as::<_, PgUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE id = $1"
            ))
            .bind(uuid)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(UserRow::from))
        }
        DbBackend::Sqlite(pool) => {
            let row = sqlx::query_as::<_, SqliteUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE id = ?1"
            ))
            .bind(id)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(UserRow::from))
        }
    }
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
}

pub async fn list_candidates(backend: &DbBackend) -> Result<Vec<CandidateRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query_as::<_, CandidateRow>(
                "SELECT id::text, reference_code, full_name, notes FROM candidates ORDER BY reference_code",
            )
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, CandidateRow>("SELECT id, reference_code, full_name, notes FROM candidates ORDER BY reference_code")
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
            sqlx::query_as::<_, CandidateRow>(
                "SELECT id::text, reference_code, full_name, notes FROM candidates WHERE id = $1",
            )
            .bind(uuid)
            .fetch_optional(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, CandidateRow>(
                "SELECT id, reference_code, full_name, notes FROM candidates WHERE id = ?1",
            )
            .bind(id)
            .fetch_optional(pool)
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
    pub top_k: Option<i64>,
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
/// `org_scope` implements object-level authorization (madde 12-13) at the
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

/// Persists a search attempt that failed before (or while) writing its
/// candidate results — see `create_search_with_candidates`. Distinct from
/// that function: this is a single, non-transactional insert, used only
/// after the transactional attempt has already rolled back, so the
/// failure itself has a durable, queryable record instead of vanishing
/// silently.
#[allow(clippy::too_many_arguments)]
pub async fn record_failed_search(
    backend: &DbBackend,
    case_reference: &str,
    purpose: &str,
    requested_by: &str,
    requested_by_name: &str,
    latitude: Option<f64>,
    longitude: Option<f64>,
    top_k: i64,
    failure_code: &str,
    failure_message_key: &str,
    organization_id: Option<&str>,
) -> Result<Option<SearchRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(requester_uuid) = Uuid::parse_str(requested_by) else {
                return Ok(None);
            };
            let org_uuid = organization_id.and_then(|v| Uuid::parse_str(v).ok());
            sqlx::query_as::<_, SearchRow>(&format!(
                "INSERT INTO searches (case_reference, purpose, requested_by, requested_by_name, latitude, longitude,
                 top_k, status, started_at, completed_at, failure_code, failure_message_key, organization_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'failed', NOW(), NOW(), $8, $9, $10) RETURNING {SEARCH_COLUMNS_PG}"
            ))
            .bind(case_reference)
            .bind(purpose)
            .bind(requester_uuid)
            .bind(requested_by_name)
            .bind(latitude)
            .bind(longitude)
            .bind(top_k)
            .bind(failure_code)
            .bind(failure_message_key)
            .bind(org_uuid)
            .fetch_one(pool)
            .await
            .map(Some)
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO searches (id, case_reference, purpose, requested_by, requested_by_name, latitude, longitude,
                 top_k, status, started_at, completed_at, failure_code, failure_message_key, organization_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'failed', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                 strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?9, ?10, ?11)",
            )
            .bind(&id)
            .bind(case_reference)
            .bind(purpose)
            .bind(requested_by)
            .bind(requested_by_name)
            .bind(latitude)
            .bind(longitude)
            .bind(top_k)
            .bind(failure_code)
            .bind(failure_message_key)
            .bind(organization_id)
            .execute(pool)
            .await?;
            load_search_by_id(backend, &id).await
        }
    }
}

/// Atomically creates a search and every one of its candidate results:
/// `BEGIN`, insert the search row, insert each candidate row, mark the
/// search `completed`, `COMMIT`. If any step fails, the whole attempt is
/// rolled back — no partial candidate list is ever left visible for a
/// search that didn't fully succeed (see CLAUDE.md's transactional-search
/// requirement). On failure, the caller is expected to call
/// `record_failed_search` separately to leave a durable failure record.
#[allow(clippy::too_many_arguments)]
pub async fn create_search_with_candidates(
    backend: &DbBackend,
    case_reference: &str,
    purpose: &str,
    requested_by: &str,
    requested_by_name: &str,
    latitude: Option<f64>,
    longitude: Option<f64>,
    top_k: i64,
    scored: &[(String, f64)],
    organization_id: Option<&str>,
) -> Result<SearchRow, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let requester_uuid = Uuid::parse_str(requested_by)
                .map_err(|e| sqlx::Error::Protocol(format!("invalid requested_by uuid: {e}")))?;
            let org_uuid = organization_id.and_then(|v| Uuid::parse_str(v).ok());
            let mut tx = pool.begin().await?;
            let search: SearchRow = sqlx::query_as(&format!(
                "INSERT INTO searches (case_reference, purpose, requested_by, requested_by_name, latitude, longitude,
                 top_k, status, started_at, organization_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'processing', NOW(), $8) RETURNING {SEARCH_COLUMNS_PG}"
            ))
            .bind(case_reference)
            .bind(purpose)
            .bind(requester_uuid)
            .bind(requested_by_name)
            .bind(latitude)
            .bind(longitude)
            .bind(top_k)
            .bind(org_uuid)
            .fetch_one(&mut *tx)
            .await?;
            let search_uuid =
                Uuid::parse_str(&search.id).expect("just-inserted search id is a valid uuid");
            for (candidate_id, score) in scored {
                let candidate_uuid = Uuid::parse_str(candidate_id)
                    .map_err(|e| sqlx::Error::Protocol(format!("invalid candidate uuid: {e}")))?;
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
            Ok(completed)
        }
        DbBackend::Sqlite(pool) => {
            let mut tx = pool.begin().await?;
            let search_id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO searches (id, case_reference, purpose, requested_by, requested_by_name, latitude, longitude,
                 top_k, status, started_at, organization_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'processing', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), ?9)",
            )
            .bind(&search_id)
            .bind(case_reference)
            .bind(purpose)
            .bind(requested_by)
            .bind(requested_by_name)
            .bind(latitude)
            .bind(longitude)
            .bind(top_k)
            .bind(organization_id)
            .execute(&mut *tx)
            .await?;
            for (candidate_id, score) in scored {
                let row_id = Uuid::new_v4().to_string();
                sqlx::query("INSERT INTO search_candidates (id, search_id, candidate_id, score) VALUES (?1, ?2, ?3, ?4)")
                    .bind(&row_id)
                    .bind(&search_id)
                    .bind(candidate_id)
                    .bind(score)
                    .execute(&mut *tx)
                    .await?;
            }
            sqlx::query(
                "UPDATE searches SET status = 'completed', completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1",
            )
            .bind(&search_id)
            .execute(&mut *tx)
            .await?;
            let completed: SearchRow = sqlx::query_as(&format!(
                "SELECT {SEARCH_COLUMNS_SQLITE} FROM searches WHERE id = ?1"
            ))
            .bind(&search_id)
            .fetch_one(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(completed)
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
/// When `require_second_review` is `true` (madde 15 — four-eyes), a
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

// ── Sessions (refresh-token rotation) ───────────────────────────────
//
// One row per logical session/token family. Rotation updates the same
// row in place (new hash, new expiry, incremented counter) rather than
// inserting a fresh row per refresh — the row *is* the family's current
// state. The raw refresh token is never persisted, only its hash.

#[derive(Debug, Clone, FromRow)]
pub struct SessionRow {
    pub id: String,
    pub user_id: String,
    pub refresh_token_hash: String,
    pub token_family_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub last_used_at: String,
    pub revoked_at: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub rotation_counter: i64,
    pub created_by: Option<String>,
}

const SESSION_COLUMNS_PG: &str = "id::text, user_id::text, refresh_token_hash, token_family_id::text, created_at::text, \
     expires_at::text, last_used_at::text, revoked_at::text, user_agent, ip_address, rotation_counter, created_by";
const SESSION_COLUMNS_SQLITE: &str =
    "id, user_id, refresh_token_hash, token_family_id, created_at, \
     expires_at, last_used_at, revoked_at, user_agent, ip_address, rotation_counter, created_by";

#[allow(clippy::too_many_arguments)]
pub async fn create_session(
    backend: &DbBackend,
    user_id: &str,
    refresh_token_hash: &str,
    token_family_id: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    user_agent: Option<&str>,
    ip_address: Option<&str>,
    created_by: &str,
) -> Result<Option<SessionRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let (Ok(user_uuid), Ok(family_uuid)) =
                (Uuid::parse_str(user_id), Uuid::parse_str(token_family_id))
            else {
                return Ok(None);
            };
            sqlx::query_as::<_, SessionRow>(&format!(
                "INSERT INTO sessions (user_id, refresh_token_hash, token_family_id, expires_at, user_agent, ip_address, created_by)
                 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {SESSION_COLUMNS_PG}"
            ))
            .bind(user_uuid)
            .bind(refresh_token_hash)
            .bind(family_uuid)
            .bind(expires_at)
            .bind(user_agent)
            .bind(ip_address)
            .bind(created_by)
            .fetch_one(pool)
            .await
            .map(Some)
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO sessions (id, user_id, refresh_token_hash, token_family_id, expires_at, user_agent, ip_address, created_by)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(&id)
            .bind(user_id)
            .bind(refresh_token_hash)
            .bind(token_family_id)
            .bind(expires_at.to_rfc3339())
            .bind(user_agent)
            .bind(ip_address)
            .bind(created_by)
            .execute(pool)
            .await?;
            find_session_by_id(backend, &id).await
        }
    }
}

pub async fn find_session_by_id(
    backend: &DbBackend,
    id: &str,
) -> Result<Option<SessionRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            sqlx::query_as::<_, SessionRow>(&format!(
                "SELECT {SESSION_COLUMNS_PG} FROM sessions WHERE id = $1"
            ))
            .bind(uuid)
            .fetch_optional(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, SessionRow>(&format!(
                "SELECT {SESSION_COLUMNS_SQLITE} FROM sessions WHERE id = ?1"
            ))
            .bind(id)
            .fetch_optional(pool)
            .await
        }
    }
}

/// Looks a session up by its token family — the value carried in the
/// refresh JWT's claims, stable across rotations. Returns the row even if
/// already revoked, so callers can distinguish "unknown family" from
/// "known family, already revoked" (the latter is a reuse signal).
pub async fn find_session_by_family(
    backend: &DbBackend,
    token_family_id: &str,
) -> Result<Option<SessionRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(token_family_id) else {
                return Ok(None);
            };
            sqlx::query_as::<_, SessionRow>(&format!(
                "SELECT {SESSION_COLUMNS_PG} FROM sessions WHERE token_family_id = $1"
            ))
            .bind(uuid)
            .fetch_optional(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, SessionRow>(&format!(
                "SELECT {SESSION_COLUMNS_SQLITE} FROM sessions WHERE token_family_id = ?1"
            ))
            .bind(token_family_id)
            .fetch_optional(pool)
            .await
        }
    }
}

/// Applies token rotation to an existing, not-yet-revoked session: new
/// refresh-token hash, new expiry, `last_used_at` touched, rotation
/// counter incremented.
pub async fn rotate_session(
    backend: &DbBackend,
    session_id: &str,
    new_refresh_token_hash: &str,
    new_expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(session_id) else {
                return Ok(());
            };
            sqlx::query(
                "UPDATE sessions SET refresh_token_hash = $1, expires_at = $2, last_used_at = NOW(),
                 rotation_counter = rotation_counter + 1 WHERE id = $3 AND revoked_at IS NULL",
            )
            .bind(new_refresh_token_hash)
            .bind(new_expires_at)
            .bind(uuid)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "UPDATE sessions SET refresh_token_hash = ?1, expires_at = ?2, last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                 rotation_counter = rotation_counter + 1 WHERE id = ?3 AND revoked_at IS NULL",
            )
            .bind(new_refresh_token_hash)
            .bind(new_expires_at.to_rfc3339())
            .bind(session_id)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

pub async fn revoke_session(backend: &DbBackend, session_id: &str) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(session_id) else {
                return Ok(());
            };
            sqlx::query(
                "UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(uuid)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query("UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?1 AND revoked_at IS NULL")
                .bind(session_id)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

/// Revokes every session sharing this token family — used on refresh-token
/// reuse detection, where the whole family is considered compromised.
pub async fn revoke_session_family(
    backend: &DbBackend,
    token_family_id: &str,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(token_family_id) else {
                return Ok(());
            };
            sqlx::query("UPDATE sessions SET revoked_at = NOW() WHERE token_family_id = $1 AND revoked_at IS NULL")
                .bind(uuid)
                .execute(pool)
                .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE token_family_id = ?1 AND revoked_at IS NULL",
            )
            .bind(token_family_id)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// Revokes every active session belonging to a user — used by logout-all,
/// by ban, and (later) by role downgrade.
pub async fn revoke_all_sessions_for_user(
    backend: &DbBackend,
    user_id: &str,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(user_id) else {
                return Ok(());
            };
            sqlx::query(
                "UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
            )
            .bind(uuid)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query("UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE user_id = ?1 AND revoked_at IS NULL")
                .bind(user_id)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

/// Deletes `sessions` and `approval_tokens` rows past their `expires_at`.
/// An expired session can never be used to refresh again (see
/// `find_session_by_id`/`rotate_session`, which already reject one), and
/// an expired approval/reset/password-reset token can never be consumed
/// (see `find_approval_token_by_hash`) — both are pure storage bloat past
/// that point, not a record anything else needs to reference (unlike
/// `users`, `searches`, or `audit_events`, which stay around for
/// attribution). Returns the number of rows removed, purely for logging.
/// Called on a fixed interval from `main.rs`; see item 58 in
/// `docs/HARDENING_CHECKLIST.md`.
pub async fn purge_expired_auth_records(backend: &DbBackend) -> Result<(u64, u64), sqlx::Error> {
    let (sessions, approval_tokens) = match backend {
        DbBackend::Postgres(pool) => {
            let sessions = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW()")
                .execute(pool)
                .await?
                .rows_affected();
            let approval_tokens =
                sqlx::query("DELETE FROM approval_tokens WHERE expires_at < NOW()")
                    .execute(pool)
                    .await?
                    .rows_affected();
            (sessions, approval_tokens)
        }
        DbBackend::Sqlite(pool) => {
            let sessions = sqlx::query(
                "DELETE FROM sessions WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            )
            .execute(pool)
            .await?
            .rows_affected();
            let approval_tokens = sqlx::query(
                "DELETE FROM approval_tokens WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            )
            .execute(pool)
            .await?
            .rows_affected();
            (sessions, approval_tokens)
        }
    };
    Ok((sessions, approval_tokens))
}

// ── Approval tokens (registration approve/reject links) ────────────

#[derive(Debug, Clone, FromRow)]
pub struct ApprovalTokenRow {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub purpose: String,
    pub created_at: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
    pub result: Option<String>,
}

const APPROVAL_TOKEN_COLUMNS_PG: &str =
    "id::text, user_id::text, token_hash, purpose, created_at::text, expires_at::text, consumed_at::text, result";
const APPROVAL_TOKEN_COLUMNS_SQLITE: &str =
    "id, user_id, token_hash, purpose, created_at, expires_at, consumed_at, result";

pub async fn create_approval_token(
    backend: &DbBackend,
    user_id: &str,
    token_hash: &str,
    purpose: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<ApprovalTokenRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(user_uuid) = Uuid::parse_str(user_id) else {
                return Ok(None);
            };
            sqlx::query_as::<_, ApprovalTokenRow>(&format!(
                "INSERT INTO approval_tokens (user_id, token_hash, purpose, expires_at)
                 VALUES ($1, $2, $3, $4) RETURNING {APPROVAL_TOKEN_COLUMNS_PG}"
            ))
            .bind(user_uuid)
            .bind(token_hash)
            .bind(purpose)
            .bind(expires_at)
            .fetch_one(pool)
            .await
            .map(Some)
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO approval_tokens (id, user_id, token_hash, purpose, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&id)
            .bind(user_id)
            .bind(token_hash)
            .bind(purpose)
            .bind(expires_at.to_rfc3339())
            .execute(pool)
            .await?;
            find_approval_token_by_hash(backend, token_hash).await
        }
    }
}

pub async fn find_approval_token_by_hash(
    backend: &DbBackend,
    token_hash: &str,
) -> Result<Option<ApprovalTokenRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query_as::<_, ApprovalTokenRow>(&format!(
                "SELECT {APPROVAL_TOKEN_COLUMNS_PG} FROM approval_tokens WHERE token_hash = $1"
            ))
            .bind(token_hash)
            .fetch_optional(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, ApprovalTokenRow>(&format!(
                "SELECT {APPROVAL_TOKEN_COLUMNS_SQLITE} FROM approval_tokens WHERE token_hash = ?1"
            ))
            .bind(token_hash)
            .fetch_optional(pool)
            .await
        }
    }
}

/// Marks a not-yet-consumed approval token as consumed with the given
/// outcome (`"approved"`/`"rejected"`). Returns `false` (no rows changed)
/// if the token was already consumed or does not exist — the caller must
/// treat that as "this link no longer works", never re-apply the action.
pub async fn consume_approval_token(
    backend: &DbBackend,
    id: &str,
    result: &str,
) -> Result<bool, sqlx::Error> {
    let affected = match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(false);
            };
            sqlx::query("UPDATE approval_tokens SET consumed_at = NOW(), result = $1 WHERE id = $2 AND consumed_at IS NULL")
                .bind(result)
                .bind(uuid)
                .execute(pool)
                .await?
                .rows_affected()
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "UPDATE approval_tokens SET consumed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), result = ?1 WHERE id = ?2 AND consumed_at IS NULL",
            )
            .bind(result)
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected()
        }
    };
    Ok(affected > 0)
}
