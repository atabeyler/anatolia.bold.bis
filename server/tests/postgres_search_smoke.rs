//! Regression guard for two instances of the same class of bug as
//! `postgres_session_smoke.rs`:
//!
//! 1. `SearchRow::top_k` was declared `Option<i64>` in Rust but the
//!    underlying Postgres column is `INTEGER` (32-bit) — sqlx's Postgres
//!    decoder rejects the width mismatch outright, while SQLite's
//!    untyped storage accepted it silently on every test in the suite
//!    that runs against `AppState::for_tests()`. This broke both
//!    creating a new search (`create_queued_search`, used by
//!    `POST /v1/search/face`) and listing past ones
//!    (`list_searches_page`, used by `GET /v1/search`) on real Postgres.
//! 2. `search_candidates.score` was declared `REAL` (32-bit float) in the
//!    Postgres migration but `SearchCandidateRow::score` is `f64` — same
//!    decoder rejection, this time on `finalize_queued_search` (writing
//!    ranked candidates once the biometric pipeline finishes) and
//!    `list_search_candidates` (`GET /v1/search/{id}/status`, the
//!    frontend's poll target). This is what actually made a real search
//!    on the live deployment fail every time, right after it had already
//!    been accepted and queued.
//!
//! Opt-in, same convention as `tests/pgvector_search.rs`.

use anatolia_bis_server::db::{self, AppState};

#[tokio::test]
async fn creating_and_listing_a_search_succeeds_against_real_postgres() {
    let Some(state) = AppState::for_postgres_tests().await else {
        eprintln!(
            "skipping creating_and_listing_a_search_succeeds_against_real_postgres: \
             PGVECTOR_TEST_DATABASE_URL is not set"
        );
        return;
    };

    let user = db::create_user(
        &state.backend,
        "PGSEARCHSMOKE",
        Some("pgsearchsmoke@example.test"),
        "Search",
        "Smoke",
        None,
        None,
        "not-a-real-hash",
        "OPERATOR",
        true,
    )
    .await
    .expect("create_user should succeed")
    .expect("create_user should return the new row");

    let search = db::create_queued_search(
        &state.backend,
        "CASE-SMOKE-1",
        "smoke test purpose",
        &user.id,
        "Search Smoke",
        None,
        None,
        10,
        None,
    )
    .await
    .expect("create_queued_search must not fail decoding top_k on Postgres");
    assert_eq!(search.top_k, Some(10));

    let (listed, total) = db::list_searches_page(&state.backend, 1, 50, None)
        .await
        .expect("list_searches_page must not fail decoding top_k on Postgres");
    assert!(total >= 1);
    assert!(listed.iter().any(|row| row.id == search.id));

    let candidate = db::create_candidate(
        &state.backend,
        "CAND-SMOKE-1",
        "Smoke Candidate",
        None,
        None,
    )
    .await
    .expect("create_candidate should succeed");

    db::finalize_queued_search(
        &state.backend,
        &search.id,
        &[(candidate.id.clone(), 0.8886)],
    )
    .await
    .expect("finalize_queued_search must not fail decoding/writing score on Postgres");

    let candidates = db::list_search_candidates(&state.backend, &search.id)
        .await
        .expect("list_search_candidates must not fail decoding score on Postgres");
    assert_eq!(candidates.len(), 1);
    assert!((candidates[0].score - 0.8886).abs() < 1e-6);
}
