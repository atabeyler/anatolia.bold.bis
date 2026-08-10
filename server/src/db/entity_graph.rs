//! Entity graph (item 10 in `docs/HARDENING_CHECKLIST.md`): candidate-
//! centric relations to aliases, usernames, organizations, and websites.
//! Deliberately a star graph around the candidate (the "Person" node),
//! not a general node-to-node graph — every relation always names the
//! candidate it belongs to, so listing a candidate's graph is a single
//! indexed query and org-scoping (`entity_graph_route` in
//! `candidates.rs`) never has to walk arbitrary edges to find the owning
//! candidate.
//!
//! Two ways a relation gets recorded, both real, neither pretending to be
//! the other:
//! - **Automatic**: every OSINT evidence item with a URL becomes a
//!   `website` relation the moment it's collected (`insert_evidence`
//!   calls `insert_relation` — see `evidence.rs`) — no text extraction
//!   involved, just the URL the provider already returned.
//! - **Manual**: a human reviewer records an `alias`/`username`/
//!   `organization` (or additional `website`) relation they found while
//!   reading the evidence, via `POST /api/v1/candidates/{id}/entity-graph`.
//!   There is no automatic name/username/organization extraction from
//!   evidence text (that would be real NLP work, not attempted here) —
//!   seeing "modellenebilsin" (the schema/API can represent it) does not
//!   claim "otomatik çıkarılıyor" (it's automatically extracted).
//!
//! Always advisory, same as `entity_resolution.rs`: a relation is a
//! human- or provider-sourced claim with provenance, never an
//! automatic merge of two identities.

use sqlx::{FromRow, PgPool, SqlitePool};
use uuid::Uuid;

use super::DbBackend;

pub(super) async fn migrate_pg(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS entity_relations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            candidate_id UUID NOT NULL REFERENCES candidates(id),
            relation_type TEXT NOT NULL,
            value TEXT NOT NULL,
            evidence_id UUID REFERENCES candidate_evidence(id),
            added_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            revoked_at TIMESTAMPTZ
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_entity_relations_candidate_id \
         ON entity_relations (candidate_id)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub(super) async fn migrate_sqlite(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS entity_relations (
            id TEXT PRIMARY KEY,
            candidate_id TEXT NOT NULL,
            relation_type TEXT NOT NULL,
            value TEXT NOT NULL,
            evidence_id TEXT,
            added_by TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            revoked_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_entity_relations_candidate_id \
         ON entity_relations (candidate_id)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// The four relation types a candidate's entity graph can express. Kept
/// as plain string constants (matching `roles.rs`'s style) rather than a
/// database enum, so SQLite and Postgres store it identically.
pub mod relation_type {
    pub const ALIAS: &str = "alias";
    pub const USERNAME: &str = "username";
    pub const ORGANIZATION: &str = "organization";
    pub const WEBSITE: &str = "website";

    pub const ALL: [&str; 4] = [ALIAS, USERNAME, ORGANIZATION, WEBSITE];
}

pub fn is_valid_relation_type(value: &str) -> bool {
    relation_type::ALL.contains(&value)
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityRelationRow {
    pub id: String,
    pub candidate_id: String,
    pub relation_type: String,
    pub value: String,
    pub evidence_id: Option<String>,
    pub added_by: Option<String>,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

pub async fn insert_relation(
    backend: &DbBackend,
    candidate_id: &str,
    relation_type: &str,
    value: &str,
    evidence_id: Option<&str>,
    added_by: Option<&str>,
) -> Result<Option<EntityRelationRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(candidate_uuid) = Uuid::parse_str(candidate_id) else {
                return Ok(None);
            };
            let evidence_uuid = evidence_id.and_then(|v| Uuid::parse_str(v).ok());
            let added_by_uuid = added_by.and_then(|v| Uuid::parse_str(v).ok());
            sqlx::query_as(
                "INSERT INTO entity_relations \
                 (candidate_id, relation_type, value, evidence_id, added_by) \
                 VALUES ($1, $2, $3, $4, $5) \
                 RETURNING id::text, candidate_id::text, relation_type, value, \
                           evidence_id::text, added_by::text, created_at::text, revoked_at::text",
            )
            .bind(candidate_uuid)
            .bind(relation_type)
            .bind(value)
            .bind(evidence_uuid)
            .bind(added_by_uuid)
            .fetch_one(pool)
            .await
            .map(Some)
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO entity_relations \
                 (id, candidate_id, relation_type, value, evidence_id, added_by) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&id)
            .bind(candidate_id)
            .bind(relation_type)
            .bind(value)
            .bind(evidence_id)
            .bind(added_by)
            .execute(pool)
            .await?;
            sqlx::query_as(
                "SELECT id, candidate_id, relation_type, value, evidence_id, added_by, \
                        created_at, revoked_at \
                 FROM entity_relations WHERE id = ?1",
            )
            .bind(&id)
            .fetch_optional(pool)
            .await
        }
    }
}

pub async fn list_relations_for_candidate(
    backend: &DbBackend,
    candidate_id: &str,
) -> Result<Vec<EntityRelationRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(candidate_uuid) = Uuid::parse_str(candidate_id) else {
                return Ok(Vec::new());
            };
            sqlx::query_as(
                "SELECT id::text, candidate_id::text, relation_type, value, \
                        evidence_id::text, added_by::text, created_at::text, revoked_at::text \
                 FROM entity_relations \
                 WHERE candidate_id = $1 AND revoked_at IS NULL \
                 ORDER BY created_at DESC",
            )
            .bind(candidate_uuid)
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT id, candidate_id, relation_type, value, evidence_id, added_by, \
                        created_at, revoked_at \
                 FROM entity_relations \
                 WHERE candidate_id = ?1 AND revoked_at IS NULL \
                 ORDER BY created_at DESC",
            )
            .bind(candidate_id)
            .fetch_all(pool)
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declared_relation_type_is_valid() {
        for t in relation_type::ALL {
            assert!(is_valid_relation_type(t));
        }
    }

    #[test]
    fn an_unknown_relation_type_is_rejected() {
        assert!(!is_valid_relation_type("phone_number"));
        assert!(!is_valid_relation_type(""));
    }
}
