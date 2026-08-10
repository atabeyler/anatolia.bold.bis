//! Regression guard for a real bug that every other test in this suite is
//! structurally blind to: `AppState::for_tests()` runs against SQLite,
//! which is untyped and accepts any integer width, so a Rust struct field
//! declared wider than its actual Postgres column (`i64` reading an
//! `INTEGER`/32-bit column, for example) passes every SQLite-backed test
//! while failing every single time on real Postgres — sqlx's Postgres
//! decoder rejects a width mismatch outright. This bit `sessions.rotation_counter`
//! (declared `INTEGER` in the migration, `i64` in `SessionRow`), which
//! made `create_session` — and therefore every login, MFA or not — fail
//! unconditionally against a real Postgres database.
//!
//! Opt-in, same convention as `tests/pgvector_search.rs`: set
//! `PGVECTOR_TEST_DATABASE_URL` to a reachable Postgres connection string
//! to run it; without it, this reports itself skipped and passes
//! trivially.

use anatolia_bis_server::db::{self, AppState};

#[tokio::test]
async fn issuing_a_session_succeeds_against_real_postgres() {
    let Some(state) = AppState::for_postgres_tests().await else {
        eprintln!(
            "skipping issuing_a_session_succeeds_against_real_postgres: \
             PGVECTOR_TEST_DATABASE_URL is not set"
        );
        return;
    };

    let user = db::create_user(
        &state.backend,
        "PGSMOKE",
        Some("pgsmoke@example.test"),
        "Smoke",
        "Test",
        None,
        None,
        "not-a-real-hash",
        "OPERATOR",
        true,
    )
    .await
    .expect("create_user should succeed")
    .expect("create_user should return the new row");

    let session = db::create_session(
        &state.backend,
        &user.id,
        "refresh-token-hash",
        &uuid::Uuid::new_v4().to_string(),
        chrono::Utc::now() + chrono::Duration::days(1),
        None,
        None,
        "login",
    )
    .await
    .expect("create_session must not fail decoding its own columns on Postgres");

    assert!(
        session.is_some(),
        "create_session should return the new row"
    );
}
