//! Comparative test for the pgvector-indexed biometric search path (item
//! 2 in `docs/HARDENING_CHECKLIST.md`): on a small dataset, the indexed
//! HNSW/pgvector search and the existing brute-force in-memory scan must
//! agree on both ranking and (near enough) score.
//!
//! This is the one test in the suite that needs a *real* Postgres with
//! the `vector` extension installable — a SQLite in-memory database (what
//! every other test in this repository runs against) cannot exercise
//! this code path at all. It is opt-in: set `PGVECTOR_TEST_DATABASE_URL`
//! to a reachable Postgres connection string to run it —
//! `cargo test --test pgvector_search`. Without that variable set, the
//! test reports itself skipped and passes trivially, so it never breaks
//! `cargo test` in an environment (like ordinary CI today) that has no
//! such database available.

use anatolia_bis_server::db::{self, AppState};

fn synthetic_embedding(seed: u32) -> Vec<f32> {
    // A cheap, deterministic pseudo-random unit vector at the real
    // embedding dimension (128) — not claiming any real face-embedding
    // distribution, only exercising the same storage/search code path a
    // real SFace embedding goes through.
    let dim = anatolia_bis_server::biometric::embedding::EMBEDDING_DIM;
    let raw: Vec<f32> = (0..dim)
        .map(|i| (((seed as usize + i) * 2654435761) % 2000) as f32 / 1000.0 - 1.0)
        .collect();
    anatolia_bis_server::biometric::embedding::l2_normalize(raw)
}

#[tokio::test]
async fn indexed_and_brute_force_search_agree_on_a_small_dataset() {
    let Some(state) = AppState::for_postgres_tests().await else {
        eprintln!(
            "skipping indexed_and_brute_force_search_agree_on_a_small_dataset: \
             PGVECTOR_TEST_DATABASE_URL is not set"
        );
        return;
    };
    assert!(
        state.pgvector_search_ready,
        "PGVECTOR_TEST_DATABASE_URL is set but the pgvector extension/index could not be \
         prepared — check that Postgres has the `vector` extension available"
    );

    const MODEL_NAME: &str = "sface";

    // A fresh, unique model_version per run — this test may run
    // repeatedly against the same persistent Postgres instance (a real
    // CI database, not a throwaway per-test one like every other test's
    // SQLite in-memory backend). `search_top_k` filters strictly on
    // model_name+model_version, so a unique version scopes every search
    // below to only this run's own rows, regardless of how much leftover
    // data past runs left behind — reusing a fixed version like
    // "2021dec" would let a previous run's rows (with the exact same
    // deterministic embeddings, since `synthetic_embedding` is a pure
    // function of `i`) tie with this run's and make the indexed/
    // brute-force paths break those ties in different orders.
    // `candidates.reference_code` is `VARCHAR(20)` — keep the unique
    // prefix short enough to still leave room for the per-candidate index.
    let run_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let model_version = format!("test-{run_id}");
    let model_version = model_version.as_str();

    let mut candidate_ids = Vec::new();
    for i in 0..12u32 {
        let candidate = db::create_candidate(
            &state.backend,
            &format!("PV{run_id}{i:02}"),
            &format!("PGVector Test Candidate {i}"),
            Some("Synthetic test record — not a real person."),
            None,
        )
        .await
        .expect("create_candidate failed");
        db::insert_template(
            &state.backend,
            &candidate.id,
            MODEL_NAME,
            model_version,
            &synthetic_embedding(i),
            0.95,
            None,
            state.pgvector_search_ready,
        )
        .await
        .expect("insert_template failed");
        candidate_ids.push(candidate.id);
    }

    let probe = synthetic_embedding(3); // matches candidate index 3 exactly

    let indexed = db::search_top_k(&state.backend, MODEL_NAME, model_version, &probe, 5, true)
        .await
        .expect("indexed search failed");
    let brute_force = db::search_top_k(&state.backend, MODEL_NAME, model_version, &probe, 5, false)
        .await
        .expect("brute-force search failed");

    assert_eq!(indexed.len(), brute_force.len());
    assert_eq!(indexed.len(), 5, "expected exactly 5 results (top_k)");

    for (a, b) in indexed.iter().zip(brute_force.iter()) {
        assert_eq!(
            a.candidate_id, b.candidate_id,
            "indexed and brute-force search disagree on ranking"
        );
        assert!(
            (a.score - b.score).abs() < 1e-4,
            "indexed score {} too far from brute-force score {} for candidate {}",
            a.score,
            b.score,
            a.candidate_id
        );
    }

    // The probe is an exact copy of candidate index 3's embedding, so it
    // must be the top result on both paths, with near-perfect similarity.
    assert_eq!(indexed[0].candidate_id, candidate_ids[3]);
    assert!(indexed[0].score > 0.999);
}
