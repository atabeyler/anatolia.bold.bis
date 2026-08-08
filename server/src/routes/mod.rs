mod health;

use axum::routing::{delete, get, post};
use axum::Router;

use crate::db::AppState;
use crate::{admin, auth};

pub fn router(state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/refresh", post(auth::refresh))
        .route("/logout", post(auth::logout))
        .route("/pending-status/:user_code", get(auth::pending_status));

    let admin_routes = Router::new()
        .route("/seed-admin", post(admin::seed_admin))
        .route("/users", get(admin::list_users))
        .route("/users/:id/approve", post(admin::approve_user))
        .route("/users/:id/reject", post(admin::reject_user))
        .route("/users/:id/ban", post(admin::ban_user))
        .route("/users/:id/unban", post(admin::unban_user))
        .route("/users/:id", delete(admin::delete_user_route))
        .route("/review/:token", get(admin::review))
        .route("/quick-approve/:token", post(admin::quick_approve))
        .route("/quick-reject/:token", post(admin::quick_reject));

    Router::new()
        .route("/api/health", get(health::health))
        .route("/api/v1/users/me", get(auth::me))
        .nest("/api/v1/auth", auth_routes)
        .nest("/api/v1/admin", admin_routes)
        .with_state(state)
}
