//! Session and approval-token domain: server-side refresh-token sessions
//! (rotation, revocation) and the
//! single-use approval tokens used for the registration approve/reject
//! email flow and password reset. Split out of `db/mod.rs` as its own
//! domain module, following the same boundary `db/audit.rs` established
//! first: it depends only on the shared `DbBackend` handle, referencing
//! `users` only via an opaque `user_id` foreign key, never a join. The
//! initial `CREATE TABLE sessions`/`CREATE TABLE approval_tokens` still
//! live in `db/mod.rs`'s `migrate` (not yet moved, to match how
//! `db/audit.rs` was split: only the query/CRUD functions moved, not the
//! original schema creation).

use sqlx::FromRow;
use uuid::Uuid;

use super::DbBackend;

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
    // Matches the Postgres column's actual width (`INTEGER`, 32-bit) —
    // sqlx's Postgres decoder rejects a struct field wider than the
    // column it reads from (unlike SQLite, which is untyped and would
    // have accepted `i64` here without complaint, hiding this on every
    // SQLite-backed test run). A session realistically never rotates
    // anywhere near i32::MAX times, so this is not a real capacity limit.
    pub rotation_counter: i32,
    pub created_by: Option<String>,
}

// Every timestamptz column here is cast via `to_char(... AT TIME ZONE
// 'UTC', ...)` rather than a bare `::text` — Postgres's default
// `timestamptz::text` output ("2026-08-10 19:19:41.123456+00", a space
// separator and a bare "+00" offset) is not valid RFC 3339, so a value
// re-parsed from it in Rust (see `auth::refresh`'s `expires_at` check)
// fails unconditionally, and that failure reads as an expired/invalid
// session, not a decode error. See `db/audit.rs`'s module doc for the
// same bug in the audit hash chain, fixed the same way.
const SESSION_COLUMNS_PG: &str = "id::text, user_id::text, refresh_token_hash, token_family_id::text, \
     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, \
     to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at, \
     to_char(last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS last_used_at, \
     to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS revoked_at, \
     user_agent, ip_address, rotation_counter, created_by";
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

/// Lists a user's active (not revoked, not yet expired) sessions,
/// most-recently-used first — the "where am I signed in" / device-list
/// view. Deliberately excludes
/// `refresh_token_hash`: nothing outside `auth.rs`'s own refresh flow ever
/// needs it, and there is no reason for even an admin-facing list to
/// carry it.
pub async fn list_active_sessions_for_user(
    backend: &DbBackend,
    user_id: &str,
) -> Result<Vec<SessionRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(user_id) else {
                return Ok(Vec::new());
            };
            sqlx::query_as::<_, SessionRow>(&format!(
                "SELECT {SESSION_COLUMNS_PG} FROM sessions \
                 WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW() \
                 ORDER BY last_used_at DESC"
            ))
            .bind(uuid)
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, SessionRow>(&format!(
                "SELECT {SESSION_COLUMNS_SQLITE} FROM sessions \
                 WHERE user_id = ?1 AND revoked_at IS NULL \
                 AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
                 ORDER BY last_used_at DESC"
            ))
            .bind(user_id)
            .fetch_all(pool)
            .await
        }
    }
}

/// Revokes one session, but only if it belongs to `user_id` — the
/// ownership check a self-service "sign out this device" action needs
/// (as opposed to `revoke_session`, used internally by the refresh flow
/// itself, and `revoke_all_sessions_for_user`, used by admin actions that
/// already checked the target account). Returns whether a row was
/// actually revoked, so the route can distinguish "not yours" /
/// "already gone" from a real success.
pub async fn revoke_session_owned_by_user(
    backend: &DbBackend,
    session_id: &str,
    user_id: &str,
) -> Result<bool, sqlx::Error> {
    let rows_affected = match backend {
        DbBackend::Postgres(pool) => {
            let (Ok(session_uuid), Ok(user_uuid)) =
                (Uuid::parse_str(session_id), Uuid::parse_str(user_id))
            else {
                return Ok(false);
            };
            sqlx::query(
                "UPDATE sessions SET revoked_at = NOW() \
                 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL",
            )
            .bind(session_uuid)
            .bind(user_uuid)
            .execute(pool)
            .await?
            .rows_affected()
        }
        DbBackend::Sqlite(pool) => sqlx::query(
            "UPDATE sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
                 WHERE id = ?1 AND user_id = ?2 AND revoked_at IS NULL",
        )
        .bind(session_id)
        .bind(user_id)
        .execute(pool)
        .await?
        .rows_affected(),
    };
    Ok(rows_affected > 0)
}

/// Deletes `sessions` and `approval_tokens` rows past their `expires_at`.
/// An expired session can never be used to refresh again (see
/// `find_session_by_id`/`rotate_session`, which already reject one), and
/// an expired approval/reset/password-reset token can never be consumed
/// (see `find_approval_token_by_hash`) — both are pure storage bloat past
/// that point, not a record anything else needs to reference (unlike
/// `users`, `searches`, or `audit_events`, which stay around for
/// attribution). Returns the number of rows removed, purely for logging.
/// Called on a fixed interval from `main.rs`.
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

// Same reasoning as `SESSION_COLUMNS_PG` above: `expires_at` here is
// re-parsed in Rust (`auth::reset_password`'s expiry check), so it must
// come back as valid RFC 3339, not Postgres's default `::text` format.
const APPROVAL_TOKEN_COLUMNS_PG: &str = "id::text, user_id::text, token_hash, purpose, \
     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS created_at, \
     to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at, \
     to_char(consumed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS consumed_at, result";
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
