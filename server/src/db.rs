use std::sync::Arc;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool, SqlitePool};
use std::str::FromStr;
use uuid::Uuid;

use crate::ratelimit::RateLimiter;

#[derive(Clone)]
pub enum DbBackend {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Clone)]
pub struct AppState {
    pub backend: DbBackend,
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    /// Prefers a managed PostgreSQL database (`DATABASE_URL`) when
    /// configured. On Render (`RENDER_EXTERNAL_URL` is set by the platform
    /// itself), a missing `DATABASE_URL` is a loud startup failure rather
    /// than a silent fallback to a throwaway SQLite database that would
    /// look healthy while holding no real users — a Postgres outage should
    /// be a visible deploy failure, not confusing, unrequested data loss.
    /// Locally, an unset `DATABASE_URL` just falls back to a SQLite file.
    pub async fn new() -> Result<Self, sqlx::Error> {
        let backend = match std::env::var("DATABASE_URL") {
            Ok(url) if !url.trim().is_empty() => DbBackend::Postgres(connect_postgres(&url).await?),
            _ if std::env::var("RENDER_EXTERNAL_URL").is_ok() => {
                panic!("DATABASE_URL is required on the web deploy (RENDER_EXTERNAL_URL is set) — refusing to fall back to a throwaway SQLite database");
            }
            _ => sqlite_backend().await?,
        };
        migrate(&backend).await?;
        Ok(Self {
            backend,
            rate_limiter: Arc::new(RateLimiter::new()),
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
            rate_limiter: Arc::new(RateLimiter::new()),
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
                    sqlx::Executor::execute(conn, format!("SET search_path TO {PG_SCHEMA}, public").as_str()).await?;
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
                    status VARCHAR(20) NOT NULL DEFAULT 'completed',
                    latitude DOUBLE PRECISION,
                    longitude DOUBLE PRECISION,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                "#,
            )
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
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                )
                "#,
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
                    status TEXT NOT NULL DEFAULT 'completed',
                    latitude REAL,
                    longitude REAL,
                    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                )
                "#,
            )
            .execute(pool)
            .await?;
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
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM candidates").fetch_one(pool).await?;
    if count > 0 {
        return Ok(());
    }
    for (i, name) in MOCK_CANDIDATE_NAMES.iter().enumerate() {
        let reference_code = format!("CAND-{:04}", i + 1);
        sqlx::query("INSERT INTO candidates (reference_code, full_name, notes) VALUES ($1, $2, $3)")
            .bind(&reference_code)
            .bind(name)
            .bind("Synthetic seed record for the mock biometric provider — not a real person.")
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn seed_mock_candidates_sqlite(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM candidates").fetch_one(pool).await?;
    if count > 0 {
        return Ok(());
    }
    for (i, name) in MOCK_CANDIDATE_NAMES.iter().enumerate() {
        let id = Uuid::new_v4().to_string();
        let reference_code = format!("CAND-{:04}", i + 1);
        sqlx::query("INSERT INTO candidates (id, reference_code, full_name, notes) VALUES (?1, ?2, ?3, ?4)")
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
    pub national_id: Option<String>,
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
    national_id: Option<String>,
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
            national_id: row.national_id,
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
    national_id: Option<String>,
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
            national_id: row.national_id,
            email: row.email,
            password_hash: row.password_hash,
            role: row.role,
            is_approved: row.is_approved != 0,
            is_banned: row.is_banned != 0,
            ban_reason: row.ban_reason,
        }
    }
}

const USER_COLUMNS: &str =
    "id, user_code, first_name, last_name, national_id, email, password_hash, role, is_approved, is_banned, ban_reason";

pub async fn load_user_by_code(backend: &DbBackend, user_code: &str) -> Result<Option<UserRow>, sqlx::Error> {
    let code = user_code.trim().to_uppercase();
    match backend {
        DbBackend::Postgres(pool) => {
            let row = sqlx::query_as::<_, PgUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE user_code = $1"
            ))
            .bind(&code)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(UserRow::from))
        }
        DbBackend::Sqlite(pool) => {
            let row = sqlx::query_as::<_, SqliteUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users WHERE user_code = ?1"
            ))
            .bind(&code)
            .fetch_optional(pool)
            .await?;
            Ok(row.map(UserRow::from))
        }
    }
}

pub async fn load_user_by_id(backend: &DbBackend, id: &str) -> Result<Option<UserRow>, sqlx::Error> {
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

pub async fn list_users(backend: &DbBackend) -> Result<Vec<UserRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let rows = sqlx::query_as::<_, PgUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users ORDER BY created_at DESC"
            ))
            .fetch_all(pool)
            .await?;
            Ok(rows.into_iter().map(UserRow::from).collect())
        }
        DbBackend::Sqlite(pool) => {
            let rows = sqlx::query_as::<_, SqliteUserRow>(&format!(
                "SELECT {USER_COLUMNS} FROM users ORDER BY created_at DESC"
            ))
            .fetch_all(pool)
            .await?;
            Ok(rows.into_iter().map(UserRow::from).collect())
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
    national_id: Option<&str>,
    password_hash: &str,
    role: &str,
    is_approved: bool,
) -> Result<Option<UserRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let row = sqlx::query_as::<_, PgUserRow>(&format!(
                "INSERT INTO users (user_code, email, first_name, last_name, national_id, password_hash, role, is_approved)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 RETURNING {USER_COLUMNS}"
            ))
            .bind(user_code)
            .bind(email)
            .bind(first_name)
            .bind(last_name)
            .bind(national_id)
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
                "INSERT INTO users (id, user_code, email, first_name, last_name, national_id, password_hash, role, is_approved)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )
            .bind(&id)
            .bind(user_code)
            .bind(email)
            .bind(first_name)
            .bind(last_name)
            .bind(national_id)
            .bind(password_hash)
            .bind(role)
            .bind(is_approved as i64)
            .execute(pool)
            .await?;
            load_user_by_id(backend, &id).await
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
    national_id: Option<&str>,
    password_hash: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            sqlx::query(
                "UPDATE users SET first_name = $1, email = $2, national_id = $3, password_hash = $4, updated_at = NOW() WHERE id = $5",
            )
            .bind(first_name)
            .bind(email)
            .bind(national_id)
            .bind(password_hash)
            .bind(uuid)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "UPDATE users SET first_name = ?1, email = ?2, national_id = ?3, password_hash = ?4, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?5",
            )
            .bind(first_name)
            .bind(email)
            .bind(national_id)
            .bind(password_hash)
            .bind(id)
            .execute(pool)
            .await?;
        }
    }
    load_user_by_id(backend, id).await
}

pub async fn load_user_by_email(backend: &DbBackend, email: &str) -> Result<Option<UserRow>, sqlx::Error> {
    let email = email.trim().to_lowercase();
    match backend {
        DbBackend::Postgres(pool) => {
            let row = sqlx::query_as::<_, PgUserRow>(&format!("SELECT {USER_COLUMNS} FROM users WHERE email = $1"))
                .bind(&email)
                .fetch_optional(pool)
                .await?;
            Ok(row.map(UserRow::from))
        }
        DbBackend::Sqlite(pool) => {
            let row = sqlx::query_as::<_, SqliteUserRow>(&format!("SELECT {USER_COLUMNS} FROM users WHERE email = ?1"))
                .bind(&email)
                .fetch_optional(pool)
                .await?;
            Ok(row.map(UserRow::from))
        }
    }
}

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
        DbBackend::Sqlite(pool) => {
            sqlx::query("DELETE FROM users WHERE id = ?1")
                .bind(id)
                .execute(pool)
                .await?
                .rows_affected()
        }
    };
    Ok(affected > 0)
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

pub async fn load_candidate_by_id(backend: &DbBackend, id: &str) -> Result<Option<CandidateRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            sqlx::query_as::<_, CandidateRow>("SELECT id::text, reference_code, full_name, notes FROM candidates WHERE id = $1")
                .bind(uuid)
                .fetch_optional(pool)
                .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, CandidateRow>("SELECT id, reference_code, full_name, notes FROM candidates WHERE id = ?1")
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
    pub created_at: String,
}

const SEARCH_COLUMNS_PG: &str =
    "id::text, case_reference, purpose, requested_by::text, requested_by_name, status, latitude, longitude, created_at::text";
const SEARCH_COLUMNS_SQLITE: &str =
    "id, case_reference, purpose, requested_by, requested_by_name, status, latitude, longitude, created_at";

#[allow(clippy::too_many_arguments)]
pub async fn create_search(
    backend: &DbBackend,
    case_reference: &str,
    purpose: &str,
    requested_by: &str,
    requested_by_name: &str,
    latitude: Option<f64>,
    longitude: Option<f64>,
) -> Result<Option<SearchRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(requester_uuid) = Uuid::parse_str(requested_by) else {
                return Ok(None);
            };
            sqlx::query_as::<_, SearchRow>(&format!(
                "INSERT INTO searches (case_reference, purpose, requested_by, requested_by_name, latitude, longitude)
                 VALUES ($1, $2, $3, $4, $5, $6) RETURNING {SEARCH_COLUMNS_PG}"
            ))
            .bind(case_reference)
            .bind(purpose)
            .bind(requester_uuid)
            .bind(requested_by_name)
            .bind(latitude)
            .bind(longitude)
            .fetch_one(pool)
            .await
            .map(Some)
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO searches (id, case_reference, purpose, requested_by, requested_by_name, latitude, longitude)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(&id)
            .bind(case_reference)
            .bind(purpose)
            .bind(requested_by)
            .bind(requested_by_name)
            .bind(latitude)
            .bind(longitude)
            .execute(pool)
            .await?;
            load_search_by_id(backend, &id).await
        }
    }
}

pub async fn load_search_by_id(backend: &DbBackend, id: &str) -> Result<Option<SearchRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            sqlx::query_as::<_, SearchRow>(&format!("SELECT {SEARCH_COLUMNS_PG} FROM searches WHERE id = $1"))
                .bind(uuid)
                .fetch_optional(pool)
                .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, SearchRow>(&format!("SELECT {SEARCH_COLUMNS_SQLITE} FROM searches WHERE id = ?1"))
                .bind(id)
                .fetch_optional(pool)
                .await
        }
    }
}

pub async fn list_searches(backend: &DbBackend) -> Result<Vec<SearchRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query_as::<_, SearchRow>(&format!("SELECT {SEARCH_COLUMNS_PG} FROM searches ORDER BY created_at DESC"))
                .fetch_all(pool)
                .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, SearchRow>(&format!("SELECT {SEARCH_COLUMNS_SQLITE} FROM searches ORDER BY created_at DESC"))
                .fetch_all(pool)
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
            let (Ok(search_uuid), Ok(candidate_uuid)) = (Uuid::parse_str(search_id), Uuid::parse_str(candidate_id)) else {
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

pub async fn list_search_candidates(backend: &DbBackend, search_id: &str) -> Result<Vec<SearchCandidateRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(search_id) else {
                return Ok(vec![]);
            };
            sqlx::query_as::<_, SearchCandidateRow>(&format!("{SEARCH_CANDIDATE_SELECT_PG} WHERE sc.search_id = $1 ORDER BY sc.score DESC"))
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

/// Sets a candidate's review status (`confirmed`/`rejected`) within one
/// search. This is the one explicit human verification action that sets
/// "Confirmed Identity" — never derived automatically from a score.
pub async fn set_search_candidate_status(
    backend: &DbBackend,
    search_id: &str,
    candidate_id: &str,
    status: &str,
    reviewed_by: &str,
    reviewed_by_name: &str,
) -> Result<Option<SearchCandidateRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let (Ok(search_uuid), Ok(candidate_uuid), Ok(reviewer_uuid)) =
                (Uuid::parse_str(search_id), Uuid::parse_str(candidate_id), Uuid::parse_str(reviewed_by))
            else {
                return Ok(None);
            };
            sqlx::query(
                "UPDATE search_candidates SET status = $1, reviewed_by = $2, reviewed_by_name = $3, reviewed_at = NOW()
                 WHERE search_id = $4 AND candidate_id = $5",
            )
            .bind(status)
            .bind(reviewer_uuid)
            .bind(reviewed_by_name)
            .bind(search_uuid)
            .bind(candidate_uuid)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "UPDATE search_candidates SET status = ?1, reviewed_by = ?2, reviewed_by_name = ?3,
                 reviewed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE search_id = ?4 AND candidate_id = ?5",
            )
            .bind(status)
            .bind(reviewed_by)
            .bind(reviewed_by_name)
            .bind(search_id)
            .bind(candidate_id)
            .execute(pool)
            .await?;
        }
    }
    list_search_candidates(backend, search_id)
        .await
        .map(|rows| rows.into_iter().find(|row| row.candidate_id == candidate_id))
}
