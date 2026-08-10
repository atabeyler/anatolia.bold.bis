//! Regression guard for the same class of bug as
//! `postgres_session_smoke.rs`: `SearchRow::top_k` was declared
//! `Option<i64>` in Rust but the underlying Postgres column is
//! `INTEGER` (32-bit) — sqlx's Postgres decoder rejects the width
//! mismatch outright, while SQLite's untyped storage accepted it
//! silently on every test in the suite that runs against
//! `AppState::for_tests()`. This broke both creating a new search
//! (`create_queued_search`, used by `POST /v1/search/face`) and listing
//! past ones (`list_searches_page`, used by `GET /v1/search`) on real
//! Postgres.
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
}
