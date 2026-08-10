//! Multi-factor authentication (TOTP) persistence. Split out as its own
//! domain module — MFA credentials and recovery codes have no dependency
//! on any other table
//! beyond the shared `DbBackend` handle and a `user_id`.
//!
//! `mfa_credentials.secret` holds the raw TOTP secret (base32-encoded), not
//! a bearer token, so it is not hashed the way session/approval tokens are
//! — verification requires *computing* a code from it, not just comparing
//! it. It is never returned by any route once enrollment is confirmed (see
//! `mfa.rs`), and never logged or placed in an audit event.
//!
//! `mfa_recovery_codes.code_hash` is a hash (matching the convention used
//! for session/approval/reset tokens elsewhere in `db/mod.rs`) because a
//! recovery code *is* a bearer secret: possessing the raw value is
//! sufficient to use it, so it must not be recoverable from a database
//! read the way the TOTP secret needs to be.

use sqlx::{FromRow, PgPool, SqlitePool};
use uuid::Uuid;

use super::DbBackend;

pub(super) async fn migrate_pg(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mfa_credentials (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL UNIQUE,
            secret TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            enabled_at TIMESTAMPTZ,
            last_used_at TIMESTAMPTZ
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL,
            code_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            used_at TIMESTAMPTZ
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes (user_id)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub(super) async fn migrate_sqlite(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mfa_credentials (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL UNIQUE,
            secret TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            enabled_at TEXT,
            last_used_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            used_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes (user_id)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

#[derive(Debug, Clone, FromRow)]
pub struct MfaCredentialRow {
    pub id: String,
    pub user_id: String,
    pub secret: String,
    pub enabled_at: Option<String>,
    pub last_used_at: Option<String>,
}

const MFA_CREDENTIAL_COLUMNS_PG: &str =
    "id::text, user_id::text, secret, enabled_at::text, last_used_at::text";
const MFA_CREDENTIAL_COLUMNS_SQLITE: &str = "id, user_id, secret, enabled_at, last_used_at";

/// Fetches the MFA credential row for a user, whether pending (not yet
/// confirmed — `enabled_at IS NULL`) or fully enabled.
pub async fn find_mfa_credential(
    backend: &DbBackend,
    user_id: &str,
) -> Result<Option<MfaCredentialRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uid) = Uuid::parse_str(user_id) else {
                return Ok(None);
            };
            sqlx::query_as::<_, MfaCredentialRow>(&format!(
                "SELECT {MFA_CREDENTIAL_COLUMNS_PG} FROM mfa_credentials WHERE user_id = $1"
            ))
            .bind(uid)
            .fetch_optional(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, MfaCredentialRow>(&format!(
                "SELECT {MFA_CREDENTIAL_COLUMNS_SQLITE} FROM mfa_credentials WHERE user_id = ?1"
            ))
            .bind(user_id)
            .fetch_optional(pool)
            .await
        }
    }
}

/// Starts (or restarts) enrollment: stores a freshly generated secret as
/// *pending* (`enabled_at = NULL`). Any previously pending — but never
/// confirmed — secret for this user is replaced; a previously *enabled*
/// credential is left untouched by this alone (callers must not call this
/// for an already-enabled user without deliberately intending to replace
/// it, since `confirm_mfa_enrollment` will overwrite `enabled_at`).
pub async fn upsert_pending_mfa_credential(
    backend: &DbBackend,
    user_id: &str,
    secret: &str,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uid) = Uuid::parse_str(user_id) else {
                return Err(sqlx::Error::RowNotFound);
            };
            sqlx::query(
                "INSERT INTO mfa_credentials (user_id, secret, enabled_at, last_used_at)
                 VALUES ($1, $2, NULL, NULL)
                 ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, enabled_at = NULL",
            )
            .bind(uid)
            .bind(secret)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO mfa_credentials (id, user_id, secret, enabled_at, last_used_at)
                 VALUES (?1, ?2, ?3, NULL, NULL)
                 ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, enabled_at = NULL",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(secret)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// Confirms a pending credential (sets `enabled_at`). Returns `false` if
/// there is no pending credential for this user matching `secret` — this
/// intentionally re-checks the secret rather than trusting the caller, so
/// a stale enrollment attempt against a since-replaced pending secret
/// cannot be confirmed.
pub async fn enable_mfa_credential(
    backend: &DbBackend,
    user_id: &str,
    secret: &str,
) -> Result<bool, sqlx::Error> {
    let rows_affected = match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uid) = Uuid::parse_str(user_id) else {
                return Ok(false);
            };
            sqlx::query(
                "UPDATE mfa_credentials SET enabled_at = NOW()
                 WHERE user_id = $1 AND secret = $2",
            )
            .bind(uid)
            .bind(secret)
            .execute(pool)
            .await?
            .rows_affected()
        }
        DbBackend::Sqlite(pool) => sqlx::query(
            "UPDATE mfa_credentials SET enabled_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE user_id = ?1 AND secret = ?2",
        )
        .bind(user_id)
        .bind(secret)
        .execute(pool)
        .await?
        .rows_affected(),
    };
    Ok(rows_affected > 0)
}

pub async fn touch_mfa_last_used(backend: &DbBackend, user_id: &str) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uid) = Uuid::parse_str(user_id) else {
                return Ok(());
            };
            sqlx::query("UPDATE mfa_credentials SET last_used_at = NOW() WHERE user_id = $1")
                .bind(uid)
                .execute(pool)
                .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "UPDATE mfa_credentials SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
                 WHERE user_id = ?1",
            )
            .bind(user_id)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// Removes MFA entirely for a user (disable, or admin reset) — deletes the
/// credential and every recovery code so a subsequent enrollment starts
/// clean.
pub async fn delete_mfa_credential(backend: &DbBackend, user_id: &str) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uid) = Uuid::parse_str(user_id) else {
                return Ok(());
            };
            sqlx::query("DELETE FROM mfa_credentials WHERE user_id = $1")
                .bind(uid)
                .execute(pool)
                .await?;
            sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
                .bind(uid)
                .execute(pool)
                .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query("DELETE FROM mfa_credentials WHERE user_id = ?1")
                .bind(user_id)
                .execute(pool)
                .await?;
            sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = ?1")
                .bind(user_id)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

/// Replaces every recovery code for a user with a fresh set (issued once,
/// at enrollment confirmation time — see `mfa.rs`).
pub async fn replace_recovery_codes(
    backend: &DbBackend,
    user_id: &str,
    code_hashes: &[String],
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uid) = Uuid::parse_str(user_id) else {
                return Ok(());
            };
            sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = $1")
                .bind(uid)
                .execute(pool)
                .await?;
            for hash in code_hashes {
                sqlx::query("INSERT INTO mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)")
                    .bind(uid)
                    .bind(hash)
                    .execute(pool)
                    .await?;
            }
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query("DELETE FROM mfa_recovery_codes WHERE user_id = ?1")
                .bind(user_id)
                .execute(pool)
                .await?;
            for hash in code_hashes {
                sqlx::query(
                    "INSERT INTO mfa_recovery_codes (id, user_id, code_hash) VALUES (?1, ?2, ?3)",
                )
                .bind(Uuid::new_v4().to_string())
                .bind(user_id)
                .bind(hash)
                .execute(pool)
                .await?;
            }
        }
    }
    Ok(())
}

/// Atomically consumes a recovery code (`used_at IS NULL` guard in the
/// `WHERE` clause means a concurrent replay of the same code can never
/// succeed twice). Returns `true` if a matching, unused code was found and
/// consumed.
pub async fn consume_recovery_code(
    backend: &DbBackend,
    user_id: &str,
    code_hash: &str,
) -> Result<bool, sqlx::Error> {
    let rows_affected = match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uid) = Uuid::parse_str(user_id) else {
                return Ok(false);
            };
            sqlx::query(
                "UPDATE mfa_recovery_codes SET used_at = NOW()
                 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
            )
            .bind(uid)
            .bind(code_hash)
            .execute(pool)
            .await?
            .rows_affected()
        }
        DbBackend::Sqlite(pool) => sqlx::query(
            "UPDATE mfa_recovery_codes SET used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
        )
        .bind(user_id)
        .bind(code_hash)
        .execute(pool)
        .await?
        .rows_affected(),
    };
    Ok(rows_affected > 0)
}
