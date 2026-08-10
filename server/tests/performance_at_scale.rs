//! Performance at scale: the
//! criterion benchmarks in `server/benches/biometric_pipeline.rs` already
//! cover the in-memory `top_k_matches` scan up to 10,000 synthetic
//! templates, but never exercise the DB-backed path
//! (`db::search_top_k`) itself at scale — this fills that gap with a
//! real integration test against a populated SQLite database (the same
//! backend the test suite always runs against), asserting the search
//! completes within a generous latency bound rather than just that it
//! runs at all. Not a substitute for load-testing a live Postgres
//! deployment under concurrent traffic — that requires infrastructure
//! this environment doesn't have — but it does catch an accidental O(n²)
//! regression in the query path itself.

use anatolia_bis_server::db::{self, AppState};
use std::time::Instant;

const CANDIDATE_COUNT: usize = 1_000;
const EMBEDDING_DIM: usize = 128;

fn synthetic_embedding(seed: usize) -> Vec<f32> {
    (0..EMBEDDING_DIM)
        .map(|i| ((seed * 31 + i) % 997) as f32 / 997.0)
        .collect()
}

#[tokio::test]
async fn searching_a_thousand_candidates_completes_within_a_generous_bound() {
    let state = AppState::for_tests().await;

    for i in 0..CANDIDATE_COUNT {
        let reference_code = format!("PERF{i:015}");
        let candidate = db::create_candidate(
            &state.backend,
            &reference_code,
            &format!("Perf Candidate {i}"),
            None,
            None,
        )
        .await
        .expect("create_candidate failed");
        db::insert_template(
            &state.backend,
            &candidate.id,
            "perf-model",
            "v1",
            &synthetic_embedding(i),
            0.9,
            None,
            state.pgvector_search_ready,
        )
        .await
        .expect("insert_template failed");
    }

    let probe = synthetic_embedding(CANDIDATE_COUNT / 2);
    let started = Instant::now();
    let results = db::search_top_k(
        &state.backend,
        "perf-model",
        "v1",
        &probe,
        10,
        state.pgvector_search_ready,
    )
    .await
    .expect("search_top_k failed");
    let elapsed = started.elapsed();

    assert_eq!(results.len(), 10, "top_k should return exactly k matches");
    assert!(
        elapsed.as_secs() < 5,
        "search over {CANDIDATE_COUNT} candidates took {elapsed:?}, expected well under 5s"
    );
}
