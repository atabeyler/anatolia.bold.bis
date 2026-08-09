mod health;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::db::AppState;
use crate::{admin, audit, auth, mfa, search};

pub fn router(state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/refresh", post(auth::refresh))
        .route("/forgot-password", post(auth::forgot_password))
        .route("/reset-password", post(auth::reset_password))
        .route("/logout", post(auth::logout))
        .route("/logout-all", post(auth::logout_all))
        .route(
            "/registration-status/:tracking_token",
            get(auth::registration_status),
        )
        .route("/mfa/enroll", post(mfa::enroll))
        .route("/mfa/enroll/confirm", post(mfa::enroll_confirm))
        .route("/mfa/disable", post(mfa::disable))
        .route("/mfa/challenge/enroll", post(mfa::challenge_enroll))
        .route(
            "/mfa/challenge/enroll/confirm",
            post(mfa::challenge_enroll_confirm),
        )
        .route("/mfa/challenge/verify", post(mfa::challenge_verify));

    let admin_routes = Router::new()
        .route("/seed-admin", post(admin::seed_admin))
        .route(
            "/users",
            get(admin::list_users).post(admin::create_user_route),
        )
        .route("/users/:id/approve", post(admin::approve_user))
        .route("/users/:id/reject", post(admin::reject_user))
        .route("/users/:id/ban", post(admin::ban_user))
        .route("/users/:id/unban", post(admin::unban_user))
        .route("/users/:id/mfa-reset", post(admin::mfa_reset_route))
        .route(
            "/users/:id",
            delete(admin::delete_user_route).patch(admin::update_user_route),
        )
        .route("/review/:token", get(admin::review))
        .route("/quick-approve/:token", post(admin::quick_approve))
        .route("/quick-reject/:token", post(admin::quick_reject));

    let search_routes = Router::new()
        .route("/face", post(search::create_search_route))
        .route("/", get(search::list_searches_route))
        .route("/:search_id", get(search::get_search_route))
        .route(
            "/:search_id/candidates",
            get(search::get_search_candidates_route),
        )
        .route(
            "/:search_id/candidates/:candidate_id/history",
            get(search::get_candidate_history_route),
        );

    let candidate_routes = Router::new()
        .route("/:candidate_id", get(search::get_candidate_route))
        .route(
            "/:candidate_id/verify",
            post(search::verify_candidate_route),
        )
        .route(
            "/:candidate_id/reject",
            post(search::reject_candidate_route),
        )
        .route(
            "/:candidate_id/inconclusive",
            post(search::mark_candidate_inconclusive_route),
        );

    Router::new()
        .route("/api/health", get(health::health))
        .route("/api/health/ready", get(health::ready))
        .route("/api/v1/users/me", get(auth::me))
        .route("/api/v1/audit", get(audit::list_audit_events_route))
        .nest("/api/v1/auth", auth_routes)
        .nest("/api/v1/admin", admin_routes)
        .nest("/api/v1/search", search_routes)
        .nest("/api/v1/candidates", candidate_routes)
        .with_state(state)
}
