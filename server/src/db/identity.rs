//! Identity/user-account domain: the `users` table and every query
//! against it — lookup, listing,
//! creation, moderation flags (approve/ban/role), profile edits, password
//! updates, and soft/hard delete. Split out of `db/mod.rs` as its own
//! domain module, following the same boundary `db/audit.rs` established
//! first: it depends only on the shared `DbBackend` handle plus
//! `crate::roles`, and nothing outside this file calls into its private
//! helpers. The initial `CREATE TABLE users` still lives in `db/mod.rs`'s
//! `migrate` (not yet moved, to match how `db/audit.rs` was split: only
//! the query/CRUD functions moved, not the original schema creation).

use sqlx::FromRow;
use uuid::Uuid;

use super::DbBackend;

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

/// Server-side paginated variant of `list_users`. `list_users` (unpaged) is kept for
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
            // `to_char(... AT TIME ZONE 'UTC', ...)` rather than a bare
            // `::text` cast — `auth::registration_status` re-parses
            // `expires_at` in Rust, and Postgres's default `::text`
            // output isn't valid RFC 3339 (see `db/audit.rs`'s module doc
            // for the same bug elsewhere, fixed the same way).
            let row = sqlx::query(
                "SELECT is_approved, is_banned, \
                 to_char(registration_tracking_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at \
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
