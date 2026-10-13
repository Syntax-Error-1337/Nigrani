mod auth;
mod routes_auth;
mod routes_sites;
pub mod state;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use self::routes_auth::{list_users, login, me, refresh};
use self::routes_sites::{create_gate, create_site, list_gates, list_sites};
use self::state::AppState;
use crate::core::AppResult;

pub async fn health() -> &'static str {
    "ok"
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/me", get(me))
        .route("/users", get(list_users))
        .route("/sites", get(list_sites).post(create_site))
        .route("/sites/:site_id/gates", get(list_gates).post(create_gate))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Bind and serve; split out so tests can build the router without serving.
pub async fn serve(state: AppState, addr: std::net::SocketAddr) -> AppResult<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind {addr}: {e}"))?;
    tracing::info!(%addr, "serving");
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("serve failed: {e}"))?;
    Ok(())
}
