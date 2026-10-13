mod auth;
pub use auth::require_permission;
pub mod rate_limit;
mod routes_auth;
mod routes_kyc;
mod routes_sites;
pub mod state;
mod routes_forensics;
mod routes_gate;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use self::routes_auth::{list_users, login, me, refresh};
use self::routes_forensics::{
    create_incident, enroll_embedding, list_incidents, search_embeddings, site_heatmap,
};
use self::routes_gate::{download_snapshot, gate_log, record_event, upload_snapshot};
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
        .route("/sites/:site_id/gates/:gate_id/events", post(record_event))
        .route("/sites/:site_id/gates/:gate_id/log", get(gate_log))
        .route("/snapshots", post(upload_snapshot))
        .route("/snapshots/:key", get(download_snapshot))
        .route("/forensics/embeddings", post(enroll_embedding))
        .route("/forensics/search", post(search_embeddings))
        .route("/sites/:site_id/incidents", post(create_incident).get(list_incidents))
        .route("/sites/:site_id/heatmap", get(site_heatmap))
        .merge(kyc_submit)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Bind and serve with graceful shutdown; split out so tests can build
/// the router without serving.
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
    .with_graceful_shutdown(async {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("shutdown signal received");
    })
    .await
    .map_err(|e| anyhow::anyhow!("serve failed: {e}"))?;
    Ok(())
}
