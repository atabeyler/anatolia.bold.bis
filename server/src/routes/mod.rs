mod health;

use axum::routing::get;
use axum::Router;

pub fn router() -> Router {
    Router::new().route("/api/health", get(health::health))
}
