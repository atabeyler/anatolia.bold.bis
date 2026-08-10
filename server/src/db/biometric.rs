//! Biometric template storage: one row per enrolled reference
//! embedding, linked to a `candidates` row. Split out as its own domain
//! module.
//!
//! Embeddings are stored as a JSON array of floats (in the `embedding`
//! column, on both backends) so a plain, correct O(n) linear
//! cosine-similarity scan (`top_k_matches`) always works identically on
//! PostgreSQL and SQLite, with no extension dependency. On PostgreSQL,
//! *in addition*, `insert_template` also writes the same embedding into a
//! native `vector(EMBEDDING_DIM)` column (`embedding_vector`) — see
//! `ensure_pgvector_index` — behind an HNSW index using cosine distance,
//! so `search_top_k` can serve a real Top-K search in `O(log n)` instead
//! of scanning every row, via the `pgvector` extension.
//!
//! The `pgvector` extension is not guaranteed to be installable on every
//! Postgres host (a managed provider may not allow-list it). Rather than
//! fail startup over this, `ensure_pgvector_index` fails soft: if the
//! `CREATE EXTENSION`/`ALTER TABLE`/`CREATE INDEX` sequence cannot
//! complete, it logs a clear warning and returns `false`. `AppState`
//! records that flag once at startup (`pgvector_search_ready`) and
//! `search_top_k` uses it to choose explicitly, on every search, between
//! the indexed path and the brute-force scan — so "no index" is a visible
//! runtime mode, never a silent, unexplained one. SQLite never has an
//! index; it always uses the brute-force scan.
//!
//! A template is only ever compared against another template from the
//! *same* `model_name`/`model_version` — comparing embeddings produced by
//! different model versions would silently produce meaningless scores, so
//! every query filters on both.

use sqlx::{FromRow, PgPool, SqlitePool};
use uuid::Uuid;

use super::DbBackend;
use crate::biometric::embedding::{cosine_similarity, EMBEDDING_DIM};

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
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS biometric_thresholds (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            model_name TEXT NOT NULL,
            model_version TEXT NOT NULL,
            threshold DOUBLE PRECISION NOT NULL,
            equal_error_rate DOUBLE PRECISION NOT NULL,
            pair_count BIGINT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (model_name, model_version)
        )
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Attempts to enable indexed pgvector search: the `vector` extension, a
/// native `embedding_vector vector(EMBEDDING_DIM)` column alongside the
/// existing JSON `embedding` column, and an HNSW index over it using
/// cosine distance. Fails soft — a Postgres host that doesn't allow the
/// extension (common on managed providers without an explicit opt-in)
/// logs a warning and leaves the deployment on the brute-force scan
/// rather than refusing to start. Idempotent: safe to call on every
/// startup.
pub(super) async fn ensure_pgvector_index(pool: &PgPool) -> bool {
    if let Err(err) = sqlx::query("CREATE EXTENSION IF NOT EXISTS vector")
        .execute(pool)
        .await
    {
        tracing::warn!(
            error = %err,
            "pgvector extension unavailable; biometric search will use the brute-force \
             in-memory scan"
        );
        return false;
    }
    if let Err(err) = sqlx::query(&format!(
        "ALTER TABLE biometric_templates ADD COLUMN IF NOT EXISTS embedding_vector vector({EMBEDDING_DIM})"
    ))
    .execute(pool)
    .await
    {
        tracing::warn!(
            error = %err,
            "could not add biometric_templates.embedding_vector; falling back to the \
             brute-force scan"
        );
        return false;
    }
    if let Err(err) = sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_biometric_templates_embedding_hnsw \
         ON biometric_templates USING hnsw (embedding_vector vector_cosine_ops)",
    )
    .execute(pool)
    .await
    {
        tracing::warn!(
            error = %err,
            "could not create the HNSW index on biometric_templates.embedding_vector; \
             falling back to the brute-force scan"
        );
        return false;
    }
    tracing::info!("pgvector HNSW index ready; biometric search will use indexed lookup");
    true
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
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS biometric_thresholds (
            id TEXT PRIMARY KEY,
            model_name TEXT NOT NULL,
            model_version TEXT NOT NULL,
            threshold REAL NOT NULL,
            equal_error_rate REAL NOT NULL,
            pair_count INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            UNIQUE (model_name, model_version)
        )
        "#,
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

#[allow(clippy::too_many_arguments)]
pub async fn insert_template(
    backend: &DbBackend,
    candidate_id: &str,
    model_name: &str,
    model_version: &str,
    embedding: &[f32],
    quality_score: f64,
    source_reference: Option<&str>,
    pgvector_ready: bool,
) -> Result<Option<BiometricTemplateRow>, sqlx::Error> {
    let embedding_json = serde_json::to_string(embedding).unwrap_or_else(|_| "[]".to_string());
    let dim = embedding.len() as i32;
    match backend {
        DbBackend::Postgres(pool) => {
            let Ok(candidate_uuid) = Uuid::parse_str(candidate_id) else {
                return Ok(None);
            };
            // Only a full-dimension embedding gets a vector-column value —
            // a differently-sized embedding (a future model swap) simply
            // isn't reachable through the indexed path and falls back to
            // the brute-force scan for that row, rather than erroring.
            let vector = (embedding.len() == EMBEDDING_DIM && pgvector_ready)
                .then(|| pgvector::Vector::from(embedding.to_vec()));
            sqlx::query_as(
                "INSERT INTO biometric_templates \
                 (candidate_id, model_name, model_version, embedding_dimension, embedding, \
                  quality_score, source_reference, embedding_vector) \
                 VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8) \
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
            .bind(vector)
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

/// Top-K candidate search, choosing explicitly between the indexed
/// pgvector path (Postgres, when `pgvector_ready`) and the brute-force
/// in-memory scan (SQLite always; Postgres when the index isn't
/// available) — see the module doc comment. Both paths apply the same
/// per-candidate "best template wins" rule and the same
/// model/model-version filter.
pub async fn search_top_k(
    backend: &DbBackend,
    model_name: &str,
    model_version: &str,
    probe_embedding: &[f32],
    top_k: usize,
    pgvector_ready: bool,
) -> Result<Vec<CandidateMatch>, sqlx::Error> {
    if let DbBackend::Postgres(pool) = backend {
        if pgvector_ready && probe_embedding.len() == EMBEDDING_DIM {
            return search_top_k_indexed(pool, model_name, model_version, probe_embedding, top_k)
                .await;
        }
    }
    let templates = list_active_templates(backend, model_name, model_version).await?;
    Ok(top_k_matches(&templates, probe_embedding, top_k))
}

/// The indexed path: one query, using pgvector's `<=>` cosine-distance
/// operator against the HNSW index, `DISTINCT ON` to keep only each
/// candidate's closest template, then re-sorted and capped to `top_k`.
/// `1 - distance` converts pgvector's cosine *distance* back into the
/// same similarity scale `cosine_similarity`/`top_k_matches` use, so a
/// caller sees identical semantics regardless of which path served the
/// search.
async fn search_top_k_indexed(
    pool: &PgPool,
    model_name: &str,
    model_version: &str,
    probe_embedding: &[f32],
    top_k: usize,
) -> Result<Vec<CandidateMatch>, sqlx::Error> {
    let probe = pgvector::Vector::from(probe_embedding.to_vec());
    let rows: Vec<(String, f64)> = sqlx::query_as(
        "SELECT candidate_id, score FROM ( \
             SELECT DISTINCT ON (candidate_id) \
                    candidate_id::text AS candidate_id, \
                    (1 - (embedding_vector <=> $1))::float8 AS score \
             FROM biometric_templates \
             WHERE model_name = $2 AND model_version = $3 AND revoked_at IS NULL \
               AND embedding_vector IS NOT NULL \
             ORDER BY candidate_id, embedding_vector <=> $1 \
         ) ranked \
         ORDER BY score DESC \
         LIMIT $4",
    )
    .bind(probe)
    .bind(model_name)
    .bind(model_version)
    .bind(top_k as i64)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(candidate_id, score)| CandidateMatch {
            candidate_id,
            score,
        })
        .collect())
}

/// A calibrated FAR/FRR threshold for one model/version — see
/// `server/src/bin/calibrate.rs --save-threshold`. Advisory: nothing in
/// this codebase currently
/// *enforces* a stored threshold against search results (the biometric
/// engine returns ranked candidates, never a match/no-match verdict, per
/// CLAUDE.md's "candidates, not verdicts" principle) — this exists so a
/// real calibration run's result is durably recorded and visible
/// (`GET /api/v1/admin/biometric-thresholds`), for a human reviewer to
/// use as a reference point, not to gate anything automatically.
#[derive(Debug, Clone, FromRow, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BiometricThresholdRow {
    pub id: String,
    pub model_name: String,
    pub model_version: String,
    pub threshold: f64,
    pub equal_error_rate: f64,
    pub pair_count: i64,
    pub created_at: String,
}

/// Records (or replaces, if one already exists for this exact
/// model_name/model_version) the calibrated threshold from a real
/// `calibrate --save-threshold` run.
pub async fn save_calibrated_threshold(
    backend: &DbBackend,
    model_name: &str,
    model_version: &str,
    threshold: f64,
    equal_error_rate: f64,
    pair_count: i64,
) -> Result<(), sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO biometric_thresholds \
                 (model_name, model_version, threshold, equal_error_rate, pair_count) \
                 VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (model_name, model_version) DO UPDATE SET \
                   threshold = EXCLUDED.threshold, \
                   equal_error_rate = EXCLUDED.equal_error_rate, \
                   pair_count = EXCLUDED.pair_count, \
                   created_at = NOW()",
            )
            .bind(model_name)
            .bind(model_version)
            .bind(threshold)
            .bind(equal_error_rate)
            .bind(pair_count)
            .execute(pool)
            .await?;
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO biometric_thresholds \
                 (id, model_name, model_version, threshold, equal_error_rate, pair_count) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT (model_name, model_version) DO UPDATE SET \
                   threshold = excluded.threshold, \
                   equal_error_rate = excluded.equal_error_rate, \
                   pair_count = excluded.pair_count, \
                   created_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(model_name)
            .bind(model_version)
            .bind(threshold)
            .bind(equal_error_rate)
            .bind(pair_count)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

pub async fn list_calibrated_thresholds(
    backend: &DbBackend,
) -> Result<Vec<BiometricThresholdRow>, sqlx::Error> {
    match backend {
        DbBackend::Postgres(pool) => {
            sqlx::query_as(
                "SELECT id::text, model_name, model_version, threshold, equal_error_rate, \
                        pair_count, created_at::text \
                 FROM biometric_thresholds ORDER BY model_name, model_version",
            )
            .fetch_all(pool)
            .await
        }
        DbBackend::Sqlite(pool) => {
            sqlx::query_as(
                "SELECT id, model_name, model_version, threshold, equal_error_rate, \
                        pair_count, created_at \
                 FROM biometric_thresholds ORDER BY model_name, model_version",
            )
            .fetch_all(pool)
            .await
        }
    }
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
