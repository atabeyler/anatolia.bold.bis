//! Candidate evidence storage (P2 OSINT appendix in
//! `docs/HARDENING_CHECKLIST.md`): one row per evidence item collected by
//! an `osint::EvidenceOrchestrator` run and attached to a candidate. Split
//! out as its own domain module (see item 31 in
//! `docs/HARDENING_CHECKLIST.md`).
//!
//! An evidence row is never a verdict about the candidate — same
//! "candidates, not verdicts" principle as biometric scores in
//! CLAUDE.md — it is a piece of context for a human reviewer, with the
//! provider's own confidence and nothing more.

use sqlx::{FromRow, PgPool, SqlitePool};
use uuid::Uuid;

use super::DbBackend;
use crate::osint::EvidenceItem;

pub(super) async fn migrate_pg(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS candidate_evidence (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            candidate_id UUID NOT NULL REFERENCES candidates(id),
            source_type TEXT NOT NULL,
            provider_name TEXT NOT NULL,
            title TEXT NOT NULL,
            url TEXT,
            snippet TEXT,
            confidence_score DOUBLE PRECISION NOT NULL,
            collected_by UUID,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_candidate_evidence_candidate_id \
         ON candidate_evidence (candidate_id)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub(super) async fn migrate_sqlite(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS candidate_evidence (
            id TEXT PRIMARY KEY,
            candidate_id TEXT NOT NULL,
            source_type TEXT NOT NULL,
            provider_name TEXT NOT NULL,
            title TEXT NOT NULL,
            url TEXT,
            snippet TEXT,
            confidence_score REAL NOT NULL,
            collected_by TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_candidate_evidence_candidate_id \
         ON candidate_evidence (candidate_id)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRow {
    pub id: String,
    pub candidate_id: String,
    pub source_type: String,
    pub provider_name: String,
    pub title: String,
    pub url: Option<String>,
    pub snippet: Option<String>,
    pub confidence_score: f64,
    pub collected_by: Option<String>,
    pub created_at: String,
}

pub async fn insert_evidence(
    backend: &DbBackend,
    candidate_id: &str,
    item: &EvidenceItem,
    collected_by: Option<&str>,
) -> Result<Option<EvidenceRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(candidate_uuid) = Uuid::parse_str(candidate_id) else {
                return Ok(None);
            };
            let collected_by_uuid = collected_by.and_then(|v| Uuid::parse_str(v).ok());
            sqlx::query_as(
                "INSERT INTO candidate_evidence \
                 (candidate_id, source_type, provider_name, title, url, snippet, \
                  confidence_score, collected_by) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 RETURNING id::text, candidate_id::text, source_type, provider_name, title, \
                           url, snippet, confidence_score, collected_by::text, created_at::text",
            )
            .bind(candidate_uuid)
            .bind(&item.source_type)
            .bind(&item.provider_name)
            .bind(&item.title)
            .bind(&item.url)
            .bind(&item.snippet)
            .bind(item.confidence)
            .bind(collected_by_uuid)
            .fetch_one(pool)
            .await
            .map(Some)
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO candidate_evidence \
                 (id, candidate_id, source_type, provider_name, title, url, snippet, \
                  confidence_score, collected_by) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )
            .bind(&id)
            .bind(candidate_id)
            .bind(&item.source_type)
            .bind(&item.provider_name)
            .bind(&item.title)
            .bind(&item.url)
            .bind(&item.snippet)
            .bind(item.confidence)
            .bind(collected_by)
            .execute(pool)
            .await?;
            sqlx::query_as(
                "SELECT id, candidate_id, source_type, provider_name, title, url, snippet, \
                        confidence_score, collected_by, created_at \
                 FROM candidate_evidence WHERE id = ?1",
            )
            .bind(&id)
            .fetch_optional(pool)
            .await
        }
    }
}

pub async fn list_evidence_for_candidate(
    backend: &DbBackend,
    candidate_id: &str,
) -> Result<Vec<EvidenceRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(candidate_uuid) = Uuid::parse_str(candidate_id) else {
                return Ok(Vec::new());
            };
            sqlx::query_as(
                "SELECT id::text, candidate_id::text, source_type, provider_name, title, url, \
                        snippet, confidence_score, collected_by::text, created_at::text \
                 FROM candidate_evidence WHERE candidate_id = $1 ORDER BY created_at DESC",
            )
            .bind(candidate_uuid)
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT id, candidate_id, source_type, provider_name, title, url, snippet, \
                        confidence_score, collected_by, created_at \
                 FROM candidate_evidence WHERE candidate_id = ?1 ORDER BY created_at DESC",
            )
            .bind(candidate_id)
            .fetch_all(pool)
            .await
        }
    }
}
