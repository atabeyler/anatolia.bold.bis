//! Audit-trail persistence — the append-only `audit_events` table.
//! Split out of db.rs as its own domain module: it has no dependency on
//! the identity/session/search
//! tables beyond the shared `DbBackend` handle, so it is the cleanest
//! boundary to separate first.
//!
//! ## Tamper resistance (hash chaining)
//!
//! Every row also carries `sequence` (a strictly increasing counter),
//! `previous_hash` (the `event_hash` of the row before it, or a fixed
//! genesis value for the first row ever), and `event_hash` (a SHA-256 of
//! a canonical representation of the row's own fields plus
//! `previous_hash`). `audit_chain_state` is a single-row table holding
//! the current chain tip (`last_sequence`/`last_hash`); every insert reads
//! and advances it inside the same transaction as the row insert, so two
//! concurrent writers can never both compute their event against the same
//! `previous_hash` — one of Postgres's transaction serialization
//! mechanisms (or SQLite's single-writer lock) forces them to interleave.
//!
//! This does not by itself stop someone with direct database access from
//! rewriting history — an UPDATE/DELETE grant is what would do that, and
//! this codebase doesn't yet provision a dedicated append-only DB role.
//! What the chain buys is
//! *detectability*: `verify_chain` recomputes every row's hash from its
//! stored fields and its stored `previous_hash`, and a single altered or
//! deleted row breaks the chain from that point forward — see
//! `verify_chain` and `GET /api/v1/audit/integrity`.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, SqlitePool};
use uuid::Uuid;

use super::DbBackend;

/// Fixed 64-character placeholder standing in for "no previous event" —
/// the `previous_hash` of the very first audit event this database ever
/// records.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub(super) async fn migrate_pg(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS sequence BIGINT")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS previous_hash TEXT")
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS event_hash TEXT")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_sequence ON audit_events (sequence)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_chain_state (
            id TEXT PRIMARY KEY,
            last_sequence BIGINT NOT NULL,
            last_hash TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO audit_chain_state (id, last_sequence, last_hash) VALUES ('singleton', 0, $1)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(GENESIS_HASH)
    .execute(pool)
    .await?;
    Ok(())
}

pub(super) async fn migrate_sqlite(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let _ = sqlx::query("ALTER TABLE audit_events ADD COLUMN sequence INTEGER")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE audit_events ADD COLUMN previous_hash TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE audit_events ADD COLUMN event_hash TEXT")
        .execute(pool)
        .await;
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_sequence ON audit_events (sequence)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_chain_state (
            id TEXT PRIMARY KEY,
            last_sequence INTEGER NOT NULL,
            last_hash TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO audit_chain_state (id, last_sequence, last_hash) VALUES ('singleton', 0, ?1)",
    )
    .bind(GENESIS_HASH)
    .execute(pool)
    .await?;
    Ok(())
}

/// Input to `insert_audit_event`. Deliberately borrows almost everything —
/// callers already hold the strings (from claims, headers, DB rows) for
/// the duration of the call, so this avoids cloning them just to hand
/// them to a query builder for a few microseconds.
#[allow(clippy::too_many_arguments)]
pub struct NewAuditEvent<'a> {
    pub actor_user_id: Option<&'a str>,
    pub actor_user_code: Option<&'a str>,
    pub actor_role: Option<&'a str>,
    pub action: &'a str,
    pub request_id: &'a str,
    pub case_reference: Option<&'a str>,
    pub resource_type: Option<&'a str>,
    pub resource_id: Option<&'a str>,
    pub result: &'a str,
    pub source: Option<&'a str>,
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    /// Pre-serialized JSON text, never raw sensitive payloads (passwords,
    /// tokens, national IDs, biometric data) — see AuditService::record.
    pub metadata: Option<String>,
    pub organization_id: Option<&'a str>,
    pub organization_unit_id: Option<&'a str>,
}

/// Canonical, unambiguous string representation of one event's hashable
/// fields, `\u{1}` (SOH — never legitimately present in any of these
/// fields) as the field separator. Both `insert_audit_event` (computing a
/// new row's hash) and `verify_chain` (recomputing an existing row's hash
/// to check it) must build this identically, or every row would appear
/// tampered.
fn canonical_event_string(
    previous_hash: &str,
    timestamp: &DateTime<Utc>,
    event: &NewAuditEvent<'_>,
) -> String {
    const SEP: char = '\u{1}';
    [
        previous_hash,
        &timestamp.to_rfc3339(),
        event.actor_user_id.unwrap_or(""),
        event.actor_user_code.unwrap_or(""),
        event.actor_role.unwrap_or(""),
        event.action,
        event.request_id,
        event.case_reference.unwrap_or(""),
        event.resource_type.unwrap_or(""),
        event.resource_id.unwrap_or(""),
        event.result,
        event.source.unwrap_or(""),
        event.ip_address.unwrap_or(""),
        event.user_agent.unwrap_or(""),
        event.metadata.as_deref().unwrap_or(""),
    ]
    .join(&SEP.to_string())
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn insert_audit_event(
    backend: &DbBackend,
    event: NewAuditEvent<'_>,
) -> Result<(), sqlx::Error> {
    let timestamp = Utc::now();
    match backend {
        DbBackend::Postgres(pool) => {
            let mut tx = pool.begin().await?;
            let (last_sequence, last_hash): (i64, String) = sqlx::query_as(
                "SELECT last_sequence, last_hash FROM audit_chain_state WHERE id = 'singleton' FOR UPDATE",
            )
            .fetch_one(&mut *tx)
            .await?;
            let sequence = last_sequence + 1;
            let event_hash = sha256_hex(&canonical_event_string(&last_hash, &timestamp, &event));

            let actor_user_id = event.actor_user_id.and_then(|v| Uuid::parse_str(v).ok());
            let organization_id = event.organization_id.and_then(|v| Uuid::parse_str(v).ok());
            let organization_unit_id = event
                .organization_unit_id
                .and_then(|v| Uuid::parse_str(v).ok());
            sqlx::query(
                "INSERT INTO audit_events (
                    \"timestamp\", actor_user_id, actor_user_code, actor_role, action, request_id, case_reference,
                    resource_type, resource_id, result, source, ip_address, user_agent, metadata,
                    organization_id, organization_unit_id, sequence, previous_hash, event_hash
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15, $16, $17, $18, $19)",
            )
            .bind(timestamp)
            .bind(actor_user_id)
            .bind(event.actor_user_code)
            .bind(event.actor_role)
            .bind(event.action)
            .bind(event.request_id)
            .bind(event.case_reference)
            .bind(event.resource_type)
            .bind(event.resource_id)
            .bind(event.result)
            .bind(event.source)
            .bind(event.ip_address)
            .bind(event.user_agent)
            .bind(event.metadata)
            .bind(organization_id)
            .bind(organization_unit_id)
            .bind(sequence)
            .bind(&last_hash)
            .bind(&event_hash)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "UPDATE audit_chain_state SET last_sequence = $1, last_hash = $2 WHERE id = 'singleton'",
            )
            .bind(sequence)
            .bind(&event_hash)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
        }
        DbBackend::Sqlite(pool) => {
            let mut tx = pool.begin().await?;
            let (last_sequence, last_hash): (i64, String) = sqlx::query_as(
                "SELECT last_sequence, last_hash FROM audit_chain_state WHERE id = 'singleton'",
            )
            .fetch_one(&mut *tx)
            .await?;
            let sequence = last_sequence + 1;
            let event_hash = sha256_hex(&canonical_event_string(&last_hash, &timestamp, &event));

            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO audit_events (
                    id, timestamp, actor_user_id, actor_user_code, actor_role, action, request_id, case_reference,
                    resource_type, resource_id, result, source, ip_address, user_agent, metadata,
                    organization_id, organization_unit_id, sequence, previous_hash, event_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            )
            .bind(&id)
            .bind(timestamp.to_rfc3339())
            .bind(event.actor_user_id)
            .bind(event.actor_user_code)
            .bind(event.actor_role)
            .bind(event.action)
            .bind(event.request_id)
            .bind(event.case_reference)
            .bind(event.resource_type)
            .bind(event.resource_id)
            .bind(event.result)
            .bind(event.source)
            .bind(event.ip_address)
            .bind(event.user_agent)
            .bind(event.metadata)
            .bind(event.organization_id)
            .bind(event.organization_unit_id)
            .bind(sequence)
            .bind(&last_hash)
            .bind(&event_hash)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "UPDATE audit_chain_state SET last_sequence = ?1, last_hash = ?2 WHERE id = 'singleton'",
            )
            .bind(sequence)
            .bind(&event_hash)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct AuditEventFilter {
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub actor_user_id: Option<String>,
    pub action: Option<String>,
    pub case_reference: Option<String>,
    pub resource_type: Option<String>,
    pub result: Option<String>,
    /// Object-level authorization: `None` means unscoped
    /// (only `SYSTEM_ADMIN` passes this — see
    /// `audit::list_audit_events_route`). `Some(ids)` restricts results
    /// to events whose `organization_id` is one of `ids`, or has none at
    /// all (legacy/unassigned data stays visible).
    pub org_scope: Option<Vec<String>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditEventRow {
    pub id: String,
    pub timestamp: String,
    pub actor_user_id: Option<String>,
    pub actor_user_code: Option<String>,
    pub actor_role: Option<String>,
    pub action: String,
    pub request_id: String,
    pub case_reference: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub result: String,
    pub source: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Option<String>,
    pub organization_id: Option<String>,
    pub organization_unit_id: Option<String>,
    pub sequence: Option<i64>,
    pub previous_hash: Option<String>,
    pub event_hash: Option<String>,
}

const AUDIT_EVENT_COLUMNS_PG: &str = "id::text, \"timestamp\"::text, actor_user_id::text, actor_user_code, actor_role, \
     action, request_id, case_reference, resource_type, resource_id, result, source, ip_address, user_agent, \
     metadata::text, organization_id::text, organization_unit_id::text, sequence, previous_hash, event_hash";
const AUDIT_EVENT_COLUMNS_SQLITE: &str = "id, timestamp, actor_user_id, actor_user_code, actor_role, action, \
     request_id, case_reference, resource_type, resource_id, result, source, ip_address, user_agent, metadata, \
     organization_id, organization_unit_id, sequence, previous_hash, event_hash";

/// Server-side paginated, filtered audit query — the backing query for
/// `GET /api/v1/audit`. `page` is 1-indexed; `page_size` is clamped by the
/// caller (see routes::audit) to a sane maximum before it ever reaches
/// here. Returns `(rows, total_matching_count)` so the frontend can render
/// page controls without a second round trip.
pub async fn list_audit_events(
    backend: &DbBackend,
    filter: &AuditEventFilter,
    page: i64,
    page_size: i64,
) -> Result<(Vec<AuditEventRow>, i64), sqlx::Error> {
    let page = page.max(1);
    let page_size = page_size.clamp(1, 200);
    let offset = (page - 1) * page_size;

    match backend {
        DbBackend::Postgres(pool) => {
            let mut count_builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
                "SELECT COUNT(*) FROM audit_events WHERE 1 = 1",
            );
            push_audit_filter_pg(&mut count_builder, filter);
            let total: i64 = count_builder.build_query_scalar().fetch_one(pool).await?;

            let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
                "SELECT {AUDIT_EVENT_COLUMNS_PG} FROM audit_events WHERE 1 = 1"
            ));
            push_audit_filter_pg(&mut builder, filter);
            builder.push(" ORDER BY \"timestamp\" DESC LIMIT ");
            builder.push_bind(page_size);
            builder.push(" OFFSET ");
            builder.push_bind(offset);
            let rows = builder
                .build_query_as::<AuditEventRow>()
                .fetch_all(pool)
                .await?;
            Ok((rows, total))
        }
        DbBackend::Sqlite(pool) => {
            let mut count_builder = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
                "SELECT COUNT(*) FROM audit_events WHERE 1 = 1",
            );
            push_audit_filter_sqlite(&mut count_builder, filter);
            let total: i64 = count_builder.build_query_scalar().fetch_one(pool).await?;

            let mut builder = sqlx::QueryBuilder::<sqlx::Sqlite>::new(format!(
                "SELECT {AUDIT_EVENT_COLUMNS_SQLITE} FROM audit_events WHERE 1 = 1"
            ));
            push_audit_filter_sqlite(&mut builder, filter);
            builder.push(" ORDER BY timestamp DESC LIMIT ");
            builder.push_bind(page_size);
            builder.push(" OFFSET ");
            builder.push_bind(offset);
            let rows = builder
                .build_query_as::<AuditEventRow>()
                .fetch_all(pool)
                .await?;
            Ok((rows, total))
        }
    }
}

fn push_audit_filter_pg<'a>(
    builder: &mut sqlx::QueryBuilder<'a, sqlx::Postgres>,
    filter: &'a AuditEventFilter,
) {
    if let Some(from) = filter.date_from {
        builder.push(" AND \"timestamp\" >= ").push_bind(from);
    }
    if let Some(to) = filter.date_to {
        builder.push(" AND \"timestamp\" <= ").push_bind(to);
    }
    if let Some(actor) = filter
        .actor_user_id
        .as_deref()
        .and_then(|v| Uuid::parse_str(v).ok())
    {
        builder.push(" AND actor_user_id = ").push_bind(actor);
    }
    if let Some(action) = filter.action.as_deref() {
        builder.push(" AND action = ").push_bind(action);
    }
    if let Some(case_reference) = filter.case_reference.as_deref() {
        builder
            .push(" AND case_reference = ")
            .push_bind(case_reference);
    }
    if let Some(resource_type) = filter.resource_type.as_deref() {
        builder
            .push(" AND resource_type = ")
            .push_bind(resource_type);
    }
    if let Some(result) = filter.result.as_deref() {
        builder.push(" AND result = ").push_bind(result);
    }
    if let Some(ids) = filter.org_scope.as_deref() {
        let uuids: Vec<Uuid> = ids.iter().filter_map(|v| Uuid::parse_str(v).ok()).collect();
        builder.push(" AND (organization_id IS NULL OR organization_id = ANY(");
        builder.push_bind(uuids);
        builder.push("))");
    }
}

fn push_audit_filter_sqlite<'a>(
    builder: &mut sqlx::QueryBuilder<'a, sqlx::Sqlite>,
    filter: &'a AuditEventFilter,
) {
    if let Some(from) = filter.date_from {
        builder
            .push(" AND timestamp >= ")
            .push_bind(from.to_rfc3339());
    }
    if let Some(to) = filter.date_to {
        builder
            .push(" AND timestamp <= ")
            .push_bind(to.to_rfc3339());
    }
    if let Some(actor) = filter.actor_user_id.as_deref() {
        builder.push(" AND actor_user_id = ").push_bind(actor);
    }
    if let Some(action) = filter.action.as_deref() {
        builder.push(" AND action = ").push_bind(action);
    }
    if let Some(case_reference) = filter.case_reference.as_deref() {
        builder
            .push(" AND case_reference = ")
            .push_bind(case_reference);
    }
    if let Some(resource_type) = filter.resource_type.as_deref() {
        builder
            .push(" AND resource_type = ")
            .push_bind(resource_type);
    }
    if let Some(result) = filter.result.as_deref() {
        builder.push(" AND result = ").push_bind(result);
    }
    if let Some(ids) = filter.org_scope.as_deref() {
        if ids.is_empty() {
            builder.push(" AND organization_id IS NULL");
        } else {
            builder.push(" AND (organization_id IS NULL OR organization_id IN (");
            let mut separated = builder.separated(", ");
            for id in ids {
                separated.push_bind(id.clone());
            }
            separated.push_unseparated(")");
            builder.push(")");
        }
    }
}

/// One broken link in the chain — the row that failed to reproduce its
/// stored `event_hash` from its own fields and its stored
/// `previous_hash`, or a row whose `previous_hash` doesn't match the
/// previous row's `event_hash`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainBreak {
    pub sequence: i64,
    pub event_id: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainVerificationReport {
    pub events_checked: i64,
    pub intact: bool,
    pub breaks: Vec<ChainBreak>,
}

/// Walks every audit event in `sequence` order and recomputes each row's
/// hash from its own stored fields to confirm it matches the stored
/// `event_hash`, and that each row's `previous_hash` matches the prior
/// row's `event_hash` — i.e. that the chain established by
/// `insert_audit_event` has not been altered since. Rows written before
/// this feature shipped (`sequence IS NULL`) are skipped, not reported as
/// broken — they predate the chain and were never hashed.
pub async fn verify_chain(backend: &DbBackend) -> Result<ChainVerificationReport, sqlx::Error> {
    let rows = match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query_as::<_, AuditEventRow>(&format!(
                "SELECT {AUDIT_EVENT_COLUMNS_PG} FROM audit_events \
                 WHERE sequence IS NOT NULL ORDER BY sequence ASC"
            ))
            .fetch_all(pool)
            .await?
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as::<_, AuditEventRow>(&format!(
                "SELECT {AUDIT_EVENT_COLUMNS_SQLITE} FROM audit_events \
                 WHERE sequence IS NOT NULL ORDER BY sequence ASC"
            ))
            .fetch_all(pool)
            .await?
        }
    };

    let mut breaks = Vec::new();
    let mut expected_previous_hash = GENESIS_HASH.to_string();
    for row in &rows {
        let sequence = row.sequence.unwrap_or_default();
        let stored_previous_hash = row.previous_hash.clone().unwrap_or_default();
        let stored_event_hash = row.event_hash.clone().unwrap_or_default();

        if stored_previous_hash != expected_previous_hash {
            breaks.push(ChainBreak {
                sequence,
                event_id: row.id.clone(),
                reason: "previous_hash does not match the prior event's event_hash",
            });
        }

        let Ok(timestamp) = row.timestamp.parse::<DateTime<Utc>>() else {
            breaks.push(ChainBreak {
                sequence,
                event_id: row.id.clone(),
                reason: "stored timestamp is not parseable",
            });
            expected_previous_hash = stored_event_hash;
            continue;
        };
        let recomputed = NewAuditEvent {
            actor_user_id: row.actor_user_id.as_deref(),
            actor_user_code: row.actor_user_code.as_deref(),
            actor_role: row.actor_role.as_deref(),
            action: &row.action,
            request_id: &row.request_id,
            case_reference: row.case_reference.as_deref(),
            resource_type: row.resource_type.as_deref(),
            resource_id: row.resource_id.as_deref(),
            result: &row.result,
            source: row.source.as_deref(),
            ip_address: row.ip_address.as_deref(),
            user_agent: row.user_agent.as_deref(),
            metadata: row.metadata.clone(),
            organization_id: row.organization_id.as_deref(),
            organization_unit_id: row.organization_unit_id.as_deref(),
        };
        let recomputed_hash = sha256_hex(&canonical_event_string(
            &stored_previous_hash,
            &timestamp,
            &recomputed,
        ));
        if recomputed_hash != stored_event_hash {
            breaks.push(ChainBreak {
                sequence,
                event_id: row.id.clone(),
                reason: "event_hash does not match this row's own recomputed fields",
            });
        }

        expected_previous_hash = stored_event_hash;
    }

    Ok(ChainVerificationReport {
        events_checked: rows.len() as i64,
        intact: breaks.is_empty(),
        breaks,
    })
}
