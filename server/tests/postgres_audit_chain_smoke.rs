//! Regression guard for a real bug in the same family as
//! `postgres_session_smoke.rs`: Postgres's default `timestamptz::text`
//! cast (`2026-08-10 16:58:56.801715+00`) is not RFC 3339 (space instead
//! of `T`, bare `+00` offset), so `verify_chain`'s
//! `row.timestamp.parse::<DateTime<Utc>>()` failed on every single row on
//! real Postgres — while passing on the SQLite backend every other test
//! in this suite runs against, since SQLite's stored format was already
//! RFC 3339. The audit-integrity endpoint reported every event as broken,
//! unconditionally, on the live deployment.
//!
//! Opt-in, same convention as `tests/pgvector_search.rs`.

use anatolia_bis_server::db::{self, AppState, NewAuditEvent};

#[tokio::test]
async fn audit_chain_is_intact_after_inserts_on_real_postgres() {
    let Some(state) = AppState::for_postgres_tests().await else {
        eprintln!(
            "skipping audit_chain_is_intact_after_inserts_on_real_postgres: \
             PGVECTOR_TEST_DATABASE_URL is not set"
        );
        return;
    };

    for _ in 0..3 {
        db::insert_audit_event(
            &state.backend,
            NewAuditEvent {
                actor_user_id: None,
                actor_user_code: None,
                actor_role: None,
                action: "PG_SMOKE_TEST_ACTION",
                request_id: "pg-smoke-request",
                case_reference: None,
                resource_type: None,
                resource_id: None,
                result: "success",
                source: None,
                ip_address: None,
                user_agent: None,
                metadata: None,
                organization_id: None,
                organization_unit_id: None,
            },
        )
        .await
        .expect("insert_audit_event should succeed");
    }

    let report = db::verify_chain(&state.backend)
        .await
        .expect("verify_chain should succeed");
    assert!(
        report.intact,
        "chain should be intact on Postgres, got breaks: {:?}",
        report.breaks
    );
}
