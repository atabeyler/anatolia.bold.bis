//! Regression guard for two real bugs that every other test in this suite
//! is structurally blind to, since `AppState::for_tests()` runs against
//! SQLite:
//!
//! 1. SQLite is untyped and accepts any integer width, so a Rust struct
//!    field declared wider than its actual Postgres column (`i64` reading
//!    an `INTEGER`/32-bit column, for example) passes every SQLite-backed
//!    test while failing every single time on real Postgres — sqlx's
//!    Postgres decoder rejects a width mismatch outright. This bit
//!    `sessions.rotation_counter` (declared `INTEGER` in the migration,
//!    `i64` in `SessionRow`), which made `create_session` — and
//!    therefore every login, MFA or not — fail unconditionally against a
//!    real Postgres database.
//! 2. SQLite's stored timestamp text is already RFC 3339
//!    (`strftime('%Y-%m-%dT%H:%M:%fZ', ...)`), while Postgres's default
//!    `timestamptz::text` cast is not (space separator, bare `+00`
//!    offset) — so a value re-parsed from it in Rust
//!    (`auth::refresh`'s `expires_at` check) failed unconditionally on
//!    Postgres, bouncing every user back to the login screen on their
//!    very next page refresh. See `db/audit.rs`'s module doc for the
//!    same class of bug in the audit hash chain.
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
    .expect("create_session must not fail decoding its own columns on Postgres")
    .expect("create_session should return the new row");

    // A second, closely related bug hid behind the first: even once
    // decoding succeeded, `expires_at` came back from Postgres's default
    // `timestamptz::text` cast ("2026-08-10 19:19:41+00" — a space
    // separator, a bare "+00" offset), which is not valid RFC 3339.
    // `auth::refresh` re-parses this value on every refresh request
    // (`session.expires_at.parse::<DateTime<Utc>>()`); on real Postgres
    // that parse failed unconditionally, so every page reload/refresh
    // was treated as an expired session and bounced the user back to the
    // login screen, immediately after a successful login.
    session
        .expires_at
        .parse::<chrono::DateTime<chrono::Utc>>()
        .expect("expires_at must be valid RFC 3339, or auth::refresh will reject every session");
}
