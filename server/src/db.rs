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

async fn connect_postgres(database_url: &str) -> Result<PgPool, sqlx::Error> {
    let mut last_err: Option<sqlx::Error> = None;
    for attempt in 0..3 {
        match PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(20))
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
                    email VARCHAR(255) UNIQUE NOT NULL,
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
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                r#"
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    user_code TEXT UNIQUE NOT NULL,
                    first_name TEXT NOT NULL,
                    last_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
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
        }
    }
    Ok(())
}

#[derive(Debug, Clone, FromRow)]
pub struct UserRow {
    pub id: String,
    pub user_code: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
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
    email: String,
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
    email: String,
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
    "id, user_code, first_name, last_name, email, password_hash, role, is_approved, is_banned, ban_reason";

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
    email: &str,
    first_name: &str,
    last_name: &str,
    password_hash: &str,
    role: &str,
    is_approved: bool,
) -> Result<Option<UserRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let row = sqlx::query_as::<_, PgUserRow>(&format!(
                "INSERT INTO users (user_code, email, first_name, last_name, password_hash, role, is_approved)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 RETURNING {USER_COLUMNS}"
            ))
            .bind(user_code)
            .bind(email)
            .bind(first_name)
            .bind(last_name)
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
                "INSERT INTO users (id, user_code, email, first_name, last_name, password_hash, role, is_approved)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(&id)
            .bind(user_code)
            .bind(email)
            .bind(first_name)
            .bind(last_name)
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
