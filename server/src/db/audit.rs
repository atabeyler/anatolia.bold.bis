//! Audit-trail persistence — the append-only `audit_events` table.
//! Split out of db.rs (see item 31 in docs/HARDENING_CHECKLIST.md) as its
//! own domain module: it has no dependency on the identity/session/search
//! tables beyond the shared `DbBackend` handle, so it is the cleanest
//! boundary to separate first.

use sqlx::FromRow;
use uuid::Uuid;

use super::DbBackend;

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

pub async fn insert_audit_event(
    backend: &DbBackend,
    event: NewAuditEvent<'_>,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let actor_user_id = event.actor_user_id.and_then(|v| Uuid::parse_str(v).ok());
            let organization_id = event.organization_id.and_then(|v| Uuid::parse_str(v).ok());
            let organization_unit_id = event
                .organization_unit_id
                .and_then(|v| Uuid::parse_str(v).ok());
            sqlx::query(
                "INSERT INTO audit_events (
                    actor_user_id, actor_user_code, actor_role, action, request_id, case_reference,
                    resource_type, resource_id, result, source, ip_address, user_agent, metadata,
                    organization_id, organization_unit_id
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15)",
            )
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
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO audit_events (
                    id, actor_user_id, actor_user_code, actor_role, action, request_id, case_reference,
                    resource_type, resource_id, result, source, ip_address, user_agent, metadata,
                    organization_id, organization_unit_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            )
            .bind(&id)
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
            .execute(pool)
            .await?;
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
}

const AUDIT_EVENT_COLUMNS_PG: &str = "id::text, \"timestamp\"::text, actor_user_id::text, actor_user_code, actor_role, \
     action, request_id, case_reference, resource_type, resource_id, result, source, ip_address, user_agent, \
     metadata::text, organization_id::text, organization_unit_id::text";
const AUDIT_EVENT_COLUMNS_SQLITE: &str = "id, timestamp, actor_user_id, actor_user_code, actor_role, action, \
     request_id, case_reference, resource_type, resource_id, result, source, ip_address, user_agent, metadata, \
     organization_id, organization_unit_id";

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
}
