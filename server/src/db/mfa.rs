//! Multi-factor authentication persistence, for both the TOTP and email
//! methods (see `mfa.rs`). Split out as its own domain module — MFA
//! credentials and recovery codes have no dependency on any other table
//! beyond the shared `DbBackend` handle and a `user_id`.
//!
//! `mfa_credentials.method` (`"totp"`/`"email"`) picks which of the two
//! remaining credential fields is meaningful: `secret` holds the raw TOTP
//! secret (base32-encoded) for TOTP-method rows and is empty for
//! email-method ones; `email_code_hash`/`email_code_expires_at` hold the
//! current pending/login code for email-method rows and are `NULL` for
//! TOTP-method ones. `secret` is not hashed the way session/approval
//! tokens are — verification requires *computing* a code from it, not
//! just comparing it — but `email_code_hash` is hashed, since an emailed
//! code is a bearer secret exactly like a recovery code (see below).
//! Neither is ever returned by any route once enrollment is confirmed
//! (see `mfa.rs`), and never logged or placed in an audit event.
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
            method TEXT NOT NULL DEFAULT 'totp',
            email_code_hash TEXT,
            email_code_expires_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            enabled_at TIMESTAMPTZ,
            last_used_at TIMESTAMPTZ
        )
        "#,
    )
    .execute(pool)
    .await?;
    // Additive migration for installs created before the `method` column
    // existed — a fresh CREATE TABLE above already has it.
    sqlx::query(
        "ALTER TABLE mfa_credentials ADD COLUMN IF NOT EXISTS method TEXT NOT NULL DEFAULT 'totp'",
    )
    .execute(pool)
    .await?;
    sqlx::query("ALTER TABLE mfa_credentials ADD COLUMN IF NOT EXISTS email_code_hash TEXT")
        .execute(pool)
        .await?;
    sqlx::query(
        "ALTER TABLE mfa_credentials ADD COLUMN IF NOT EXISTS email_code_expires_at TIMESTAMPTZ",
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
            method TEXT NOT NULL DEFAULT 'totp',
            email_code_hash TEXT,
            email_code_expires_at TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            enabled_at TEXT,
            last_used_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    // Additive migration for installs created before these columns existed.
    // Older SQLite has no `ADD COLUMN IF NOT EXISTS`, so failures (column
    // already present) are simply ignored, matching the convention used
    // throughout `db/mod.rs`.
    let _ =
        sqlx::query("ALTER TABLE mfa_credentials ADD COLUMN method TEXT NOT NULL DEFAULT 'totp'")
            .execute(pool)
            .await;
    let _ = sqlx::query("ALTER TABLE mfa_credentials ADD COLUMN email_code_hash TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE mfa_credentials ADD COLUMN email_code_expires_at TEXT")
        .execute(pool)
        .await;

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
    pub method: String,
    pub email_code_hash: Option<String>,
    pub email_code_expires_at: Option<String>,
    pub enabled_at: Option<String>,
    pub last_used_at: Option<String>,
}

const MFA_CREDENTIAL_COLUMNS_PG: &str = "id::text, user_id::text, secret, method, email_code_hash, email_code_expires_at::text, enabled_at::text, last_used_at::text";
const MFA_CREDENTIAL_COLUMNS_SQLITE: &str =
    "id, user_id, secret, method, email_code_hash, email_code_expires_at, enabled_at, last_used_at";

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
                "INSERT INTO mfa_credentials (user_id, secret, method, email_code_hash, email_code_expires_at, enabled_at, last_used_at)
                 VALUES ($1, $2, 'totp', NULL, NULL, NULL, NULL)
                 ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, method = 'totp', email_code_hash = NULL, email_code_expires_at = NULL, enabled_at = NULL",
            )
            .bind(uid)
            .bind(secret)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO mfa_credentials (id, user_id, secret, method, email_code_hash, email_code_expires_at, enabled_at, last_used_at)
                 VALUES (?1, ?2, ?3, 'totp', NULL, NULL, NULL, NULL)
                 ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, method = 'totp', email_code_hash = NULL, email_code_expires_at = NULL, enabled_at = NULL",
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

/// Starts (or restarts) email-method enrollment: stores a freshly generated
/// code (hashed) as pending, alongside an empty TOTP secret — mirrors
/// `upsert_pending_mfa_credential` but for the email method, which has no
/// TOTP secret and instead carries a short-lived emailed code.
pub async fn upsert_pending_email_mfa_credential(
    backend: &DbBackend,
    user_id: &str,
    code_hash: &str,
    expires_at: &str,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uid) = Uuid::parse_str(user_id) else {
                return Err(sqlx::Error::RowNotFound);
            };
            sqlx::query(
                "INSERT INTO mfa_credentials (user_id, secret, method, email_code_hash, email_code_expires_at, enabled_at, last_used_at)
                 VALUES ($1, '', 'email', $2, $3::timestamptz, NULL, NULL)
                 ON CONFLICT (user_id) DO UPDATE SET secret = '', method = 'email', email_code_hash = EXCLUDED.email_code_hash, email_code_expires_at = EXCLUDED.email_code_expires_at, enabled_at = NULL",
            )
            .bind(uid)
            .bind(code_hash)
            .bind(expires_at)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO mfa_credentials (id, user_id, secret, method, email_code_hash, email_code_expires_at, enabled_at, last_used_at)
                 VALUES (?1, ?2, '', 'email', ?3, ?4, NULL, NULL)
                 ON CONFLICT (user_id) DO UPDATE SET secret = '', method = 'email', email_code_hash = excluded.email_code_hash, email_code_expires_at = excluded.email_code_expires_at, enabled_at = NULL",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(code_hash)
            .bind(expires_at)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// Overwrites the pending emailed code for an existing `method = 'email'`
/// credential (pending or already enabled) — used to resend a fresh code,
/// either during voluntary enrollment or a login-time challenge.
pub async fn update_email_mfa_code(
    backend: &DbBackend,
    user_id: &str,
    code_hash: &str,
    expires_at: &str,
) -> Result<bool, sqlx::Error> {
    let rows_affected = match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uid) = Uuid::parse_str(user_id) else {
                return Ok(false);
            };
            sqlx::query(
                "UPDATE mfa_credentials SET email_code_hash = $2, email_code_expires_at = $3::timestamptz
                 WHERE user_id = $1 AND method = 'email'",
            )
            .bind(uid)
            .bind(code_hash)
            .bind(expires_at)
            .execute(pool)
            .await?
            .rows_affected()
        }
        DbBackend::Sqlite(pool) => sqlx::query(
            "UPDATE mfa_credentials SET email_code_hash = ?2, email_code_expires_at = ?3
                 WHERE user_id = ?1 AND method = 'email'",
        )
        .bind(user_id)
        .bind(code_hash)
        .bind(expires_at)
        .execute(pool)
        .await?
        .rows_affected(),
    };
    Ok(rows_affected > 0)
}

/// Confirms a pending email-method credential: re-checks the emailed code
/// (and its expiry) rather than trusting the caller, exactly like
/// `enable_mfa_credential` does for TOTP secrets.
pub async fn enable_email_mfa_credential(
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
                "UPDATE mfa_credentials SET enabled_at = NOW(), email_code_hash = NULL, email_code_expires_at = NULL
                 WHERE user_id = $1 AND method = 'email' AND email_code_hash = $2 AND email_code_expires_at > NOW()",
            )
            .bind(uid)
            .bind(code_hash)
            .execute(pool)
            .await?
            .rows_affected()
        }
        DbBackend::Sqlite(pool) => sqlx::query(
            "UPDATE mfa_credentials SET enabled_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), email_code_hash = NULL, email_code_expires_at = NULL
                 WHERE user_id = ?1 AND method = 'email' AND email_code_hash = ?2 AND email_code_expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(user_id)
        .bind(code_hash)
        .execute(pool)
        .await?
        .rows_affected(),
    };
    Ok(rows_affected > 0)
}

/// Atomically consumes a login-time (or disable-time) emailed code for an
/// already-enabled `method = 'email'` credential — the `email_code_hash`
/// and expiry guard in the `WHERE` clause means a replay after the code has
/// been consumed or has expired can never succeed.
pub async fn consume_email_mfa_code(
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
                "UPDATE mfa_credentials SET email_code_hash = NULL, email_code_expires_at = NULL, last_used_at = NOW()
                 WHERE user_id = $1 AND method = 'email' AND email_code_hash = $2 AND email_code_expires_at > NOW()",
            )
            .bind(uid)
            .bind(code_hash)
            .execute(pool)
            .await?
            .rows_affected()
        }
        DbBackend::Sqlite(pool) => sqlx::query(
            "UPDATE mfa_credentials SET email_code_hash = NULL, email_code_expires_at = NULL, last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE user_id = ?1 AND method = 'email' AND email_code_hash = ?2 AND email_code_expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(user_id)
        .bind(code_hash)
        .execute(pool)
        .await?
        .rows_affected(),
    };
    Ok(rows_affected > 0)
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
