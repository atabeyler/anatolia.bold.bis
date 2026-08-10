//! `db::purge_expired_auth_records` (item 58 in
//! `docs/HARDENING_CHECKLIST.md`): expired `sessions`/`approval_tokens`
//! rows are deleted, unexpired ones are left alone.

use anatolia_bis_server::db;
use anatolia_bis_server::db::AppState;
use bcrypt::hash;
use chrono::{Duration, Utc};

#[tokio::test]
async fn purge_removes_only_expired_sessions_and_approval_tokens() {
    let state = AppState::for_tests().await;

    let user = db::create_user(
        &state.backend,
        "RETENTIONUSER",
        Some("retention@example.test"),
        "Retention",
        "Tester",
        None,
        None,
        &hash("Password1!", bcrypt::DEFAULT_COST).unwrap(),
        anatolia_bis_server::roles::OPERATOR,
        true,
    )
    .await
    .unwrap()
    .unwrap();

    // One expired and one still-valid session.
    db::create_session(
        &state.backend,
        &user.id,
        "expired-hash",
        "family-expired",
        Utc::now() - Duration::hours(1),
        None,
        None,
        "test",
    )
    .await
    .unwrap();
    let valid_session = db::create_session(
        &state.backend,
        &user.id,
        "valid-hash",
        "family-valid",
        Utc::now() + Duration::hours(1),
        None,
        None,
        "test",
    )
    .await
    .unwrap()
    .unwrap();

    // One expired and one still-valid approval token.
    db::create_approval_token(
        &state.backend,
        &user.id,
        "expired-token-hash",
        "password_reset",
        Utc::now() - Duration::hours(1),
    )
    .await
    .unwrap();
    let valid_token = db::create_approval_token(
        &state.backend,
        &user.id,
        "valid-token-hash",
        "password_reset",
        Utc::now() + Duration::hours(1),
    )
    .await
    .unwrap()
    .unwrap();

    let (sessions_purged, tokens_purged) = db::purge_expired_auth_records(&state.backend)
        .await
        .unwrap();
    assert_eq!(sessions_purged, 1);
    assert_eq!(tokens_purged, 1);

    // The still-valid rows must survive the purge.
    assert!(db::find_session_by_id(&state.backend, &valid_session.id)
        .await
        .unwrap()
        .is_some());
    assert!(
        db::find_approval_token_by_hash(&state.backend, "valid-token-hash")
            .await
            .unwrap()
            .is_some()
    );
    let _ = valid_token;

    // Running the purge again finds nothing left to remove.
    let (sessions_purged_again, tokens_purged_again) =
        db::purge_expired_auth_records(&state.backend)
            .await
            .unwrap();
    assert_eq!(sessions_purged_again, 0);
    assert_eq!(tokens_purged_again, 0);
}
