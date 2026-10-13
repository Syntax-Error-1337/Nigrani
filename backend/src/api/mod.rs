mod auth;
pub mod rate_limit;
mod routes_auth;
mod routes_kyc;
mod routes_sites;
pub mod state;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use self::routes_auth::{list_users, login, me, refresh};
use self::routes_kyc::{decide_kyc, list_kyc, press_card, submit_kyc, verify_press_card};
use self::routes_sites::{create_gate, create_site, list_gates, list_sites};
use self::state::AppState;
use crate::core::AppResult;

pub async fn health() -> &'static str {
    "ok"
}

pub fn router(state: AppState) -> Router {
    // Public pre-registration portal: per-IP fixed window (quota on AppState).
    let kyc_submit: Router<AppState> = Router::new()
        .route("/kyc/applications", post(submit_kyc))
        .route_layer(axum::middleware::from_fn(rate_limit::kyc_limiter))
        .layer(axum::Extension(state.kyc_limiter.clone()));
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/me", get(me))
        .route("/users", get(list_users))
        .route("/sites", get(list_sites).post(create_site))
        .route("/sites/:site_id/gates", get(list_gates).post(create_gate))
        .route("/kyc/applications", get(list_kyc))
        .route("/kyc/applications/:id/decide", post(decide_kyc))
        .route("/kyc/applications/:id/press-card", get(press_card))
        .route("/kyc/verify", post(verify_press_card))
        .merge(kyc_submit)
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
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
        .await
        .map_err(|e| anyhow::anyhow!("serve failed: {e}"))?;
    Ok(())
}
