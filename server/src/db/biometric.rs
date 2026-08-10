//! Biometric template storage (madde 1-6): one row per enrolled reference
//! embedding, linked to a `candidates` row. Split out as its own domain
//! module (see item 31 in `docs/HARDENING_CHECKLIST.md`).
//!
//! Embeddings are stored as a JSON array of floats rather than a native
//! vector column. This is a deliberate, documented interim choice: it
//! works identically on both PostgreSQL and SQLite without requiring the
//! `pgvector` extension, whose availability in a given deployment isn't
//! guaranteed. `pgvector` (or another dedicated vector store, behind the
//! same provider-abstraction principle CLAUDE.md requires) is the
//! documented future upgrade path once ANN indexing is actually needed —
//! see `docs/ROADMAP.md`. Similarity search here is a real, correct O(n)
//! linear cosine-similarity scan over the filtered candidate set, not an
//! indexed approximate search; that is an explicit, documented
//! performance limitation, not a faked capability.
//!
//! A template is only ever compared against another template from the
//! *same* `model_name`/`model_version` — comparing embeddings produced by
//! different model versions would silently produce meaningless scores, so
//! every query filters on both.

use sqlx::{FromRow, PgPool, SqlitePool};
use uuid::Uuid;

use super::DbBackend;
use crate::biometric::embedding::cosine_similarity;

pub(super) async fn migrate_pg(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS biometric_templates (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            candidate_id UUID NOT NULL REFERENCES candidates(id),
            model_name TEXT NOT NULL,
            model_version TEXT NOT NULL,
            embedding_dimension INTEGER NOT NULL,
            embedding JSONB NOT NULL,
            quality_score DOUBLE PRECISION NOT NULL,
            source_reference TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            revoked_at TIMESTAMPTZ
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_biometric_templates_candidate_id \
         ON biometric_templates (candidate_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_biometric_templates_model \
         ON biometric_templates (model_name, model_version)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub(super) async fn migrate_sqlite(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS biometric_templates (
            id TEXT PRIMARY KEY,
            candidate_id TEXT NOT NULL,
            model_name TEXT NOT NULL,
            model_version TEXT NOT NULL,
            embedding_dimension INTEGER NOT NULL,
            embedding TEXT NOT NULL,
            quality_score REAL NOT NULL,
            source_reference TEXT,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            revoked_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_biometric_templates_candidate_id \
         ON biometric_templates (candidate_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_biometric_templates_model \
         ON biometric_templates (model_name, model_version)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, FromRow, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricTemplateRow {
    pub id: String,
    pub candidate_id: String,
    pub model_name: String,
    pub model_version: String,
    pub embedding_dimension: i32,
    pub embedding: String,
    pub quality_score: f64,
    pub source_reference: Option<String>,
    pub created_at: String,
    pub revoked_at: Option<String>,
}

impl BiometricTemplateRow {
    pub fn embedding_vec(&self) -> Vec<f32> {
        serde_json::from_str(&self.embedding).unwrap_or_default()
    }
}

pub async fn insert_template(
    backend: &DbBackend,
    candidate_id: &str,
    model_name: &str,
    model_version: &str,
    embedding: &[f32],
    quality_score: f64,
    source_reference: Option<&str>,
) -> Result<Option<BiometricTemplateRow>, sqlx::Error> {
    let embedding_json = serde_json::to_string(embedding).unwrap_or_else(|_| "[]".to_string());
    let dim = embedding.len() as i32;
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(candidate_uuid) = Uuid::parse_str(candidate_id) else {
                return Ok(None);
            };
            sqlx::query_as(
                "INSERT INTO biometric_templates \
                 (candidate_id, model_name, model_version, embedding_dimension, embedding, \
                  quality_score, source_reference) \
                 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7) \
                 RETURNING id::text, candidate_id::text, model_name, model_version, \
                           embedding_dimension, embedding::text, quality_score, source_reference, \
                           created_at::text, revoked_at::text",
            )
            .bind(candidate_uuid)
            .bind(model_name)
            .bind(model_version)
            .bind(dim)
            .bind(&embedding_json)
            .bind(quality_score)
            .bind(source_reference)
            .fetch_one(pool)
            .await
            .map(Some)
        }
        DbBackend::Sqlite(pool) => {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO biometric_templates \
                 (id, candidate_id, model_name, model_version, embedding_dimension, embedding, \
                  quality_score, source_reference) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(&id)
            .bind(candidate_id)
            .bind(model_name)
            .bind(model_version)
            .bind(dim)
            .bind(&embedding_json)
            .bind(quality_score)
            .bind(source_reference)
            .execute(pool)
            .await?;
            sqlx::query_as(
                "SELECT id, candidate_id, model_name, model_version, embedding_dimension, \
                        embedding, quality_score, source_reference, created_at, revoked_at \
                 FROM biometric_templates WHERE id = ?1",
            )
            .bind(&id)
            .fetch_optional(pool)
            .await
        }
    }
}

pub async fn list_active_templates(
    backend: &DbBackend,
    model_name: &str,
    model_version: &str,
) -> Result<Vec<BiometricTemplateRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query_as(
                "SELECT id::text, candidate_id::text, model_name, model_version, \
                        embedding_dimension, embedding::text, quality_score, source_reference, \
                        created_at::text, revoked_at::text \
                 FROM biometric_templates \
                 WHERE model_name = $1 AND model_version = $2 AND revoked_at IS NULL",
            )
            .bind(model_name)
            .bind(model_version)
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT id, candidate_id, model_name, model_version, embedding_dimension, \
                        embedding, quality_score, source_reference, created_at, revoked_at \
                 FROM biometric_templates \
                 WHERE model_name = ?1 AND model_version = ?2 AND revoked_at IS NULL",
            )
            .bind(model_name)
            .bind(model_version)
            .fetch_all(pool)
            .await
        }
    }
}

pub async fn list_templates_for_candidate(
    backend: &DbBackend,
    candidate_id: &str,
) -> Result<Vec<BiometricTemplateRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(candidate_uuid) = Uuid::parse_str(candidate_id) else {
                return Ok(Vec::new());
            };
            sqlx::query_as(
                "SELECT id::text, candidate_id::text, model_name, model_version, \
                        embedding_dimension, embedding::text, quality_score, source_reference, \
                        created_at::text, revoked_at::text \
                 FROM biometric_templates WHERE candidate_id = $1 ORDER BY created_at DESC",
            )
            .bind(candidate_uuid)
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT id, candidate_id, model_name, model_version, embedding_dimension, \
                        embedding, quality_score, source_reference, created_at, revoked_at \
                 FROM biometric_templates WHERE candidate_id = ?1 ORDER BY created_at DESC",
            )
            .bind(candidate_id)
            .fetch_all(pool)
            .await
        }
    }
}

pub async fn revoke_template(backend: &DbBackend, template_id: &str) -> Result<bool, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(uuid) = Uuid::parse_str(template_id) else {
                return Ok(false);
            };
            let result = sqlx::query(
                "UPDATE biometric_templates SET revoked_at = NOW() \
                 WHERE id = $1 AND revoked_at IS NULL",
            )
            .bind(uuid)
            .execute(pool)
            .await?;
            Ok(result.rows_affected() > 0)
        }
        DbBackend::Sqlite(pool) => {
            let result = sqlx::query(
                "UPDATE biometric_templates SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
                 WHERE id = ?1 AND revoked_at IS NULL",
            )
            .bind(template_id)
            .execute(pool)
            .await?;
            Ok(result.rows_affected() > 0)
        }
    }
}

/// One candidate's best-matching score against `probe_embedding`, ranked
/// by that maximum (a candidate can have several enrolled templates — the
/// candidate is only as good a match as its single closest template).
pub struct CandidateMatch {
    pub candidate_id: String,
    pub score: f64,
}

/// Real cosine-similarity Top-K search over every active,
/// model/version-compatible template — an O(n) linear scan (see module
/// doc comment for why, and the documented upgrade path).
pub fn top_k_matches(
    templates: &[BiometricTemplateRow],
    probe_embedding: &[f32],
    top_k: usize,
) -> Vec<CandidateMatch> {
    use std::collections::HashMap;
    let mut best: HashMap<String, f64> = HashMap::new();
    for template in templates {
        let score = cosine_similarity(&template.embedding_vec(), probe_embedding);
        best.entry(template.candidate_id.clone())
            .and_modify(|existing| {
                if score > *existing {
                    *existing = score;
                }
            })
            .or_insert(score);
    }
    let mut ranked: Vec<CandidateMatch> = best
        .into_iter()
        .map(|(candidate_id, score)| CandidateMatch {
            candidate_id,
            score,
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    ranked.truncate(top_k);
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(candidate_id: &str, embedding: Vec<f32>) -> BiometricTemplateRow {
        BiometricTemplateRow {
            id: Uuid::new_v4().to_string(),
            candidate_id: candidate_id.to_string(),
            model_name: "sface".to_string(),
            model_version: "2021dec".to_string(),
            embedding_dimension: embedding.len() as i32,
            embedding: serde_json::to_string(&embedding).unwrap(),
            quality_score: 0.9,
            source_reference: None,
            created_at: "now".to_string(),
            revoked_at: None,
        }
    }

    #[test]
    fn top_k_ranks_by_best_matching_template_per_candidate() {
        let templates = vec![
            template("a", vec![1.0, 0.0]),
            template("a", vec![0.0, 1.0]), // candidate a's worse template
            template("b", vec![0.9, 0.1]),
        ];
        let probe = vec![1.0, 0.0];
        let ranked = top_k_matches(&templates, &probe, 10);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].candidate_id, "a");
        assert!((ranked[0].score - 1.0).abs() < 1e-6);
        assert_eq!(ranked[1].candidate_id, "b");
    }

    #[test]
    fn top_k_truncates_to_requested_size() {
        let templates = vec![
            template("a", vec![1.0, 0.0]),
            template("b", vec![0.9, 0.1]),
            template("c", vec![0.1, 0.9]),
        ];
        let probe = vec![1.0, 0.0];
        let ranked = top_k_matches(&templates, &probe, 2);
        assert_eq!(ranked.len(), 2);
    }

    #[test]
    fn embedding_vec_round_trips_through_json() {
        let row = template("a", vec![0.5, -0.25, 1.0]);
        assert_eq!(row.embedding_vec(), vec![0.5, -0.25, 1.0]);
    }
}
