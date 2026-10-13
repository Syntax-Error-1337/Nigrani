mod auth;
pub use auth::require_permission;
mod routes_audit;
mod routes_demo;
mod routes_retention;
mod routes_users;
pub mod events;
mod paging;
pub mod rate_limit;
mod request_id;
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
use self::events::events_ws;
use self::routes_audit::{list_audit, site_audit, verify_audit};
use self::routes_demo::reset_demo;
use self::routes_retention::{export_site, list_policies, run_purge, set_policy};
use self::routes_users::{change_password, create_user, set_active};
use self::routes_auth::{list_users, login, logout, logout_all, me, refresh};
use self::routes_forensics::{
    create_incident, enroll_embedding, list_incidents, search_embeddings, site_heatmap,
};
use self::routes_gate::{download_snapshot, gate_log, record_event, share_snapshot, upload_snapshot};
use self::routes_kyc::{decide_kyc, list_kyc, press_card, press_card_png, submit_kyc, verify_press_card};
use self::routes_sites::{create_gate, create_site, list_gates, list_sites};
use self::state::AppState;
use crate::core::AppResult;

pub async fn health() -> &'static str {
    "ok"
}

pub fn router(state: AppState) -> Router {
    use rate_limit::LimitRule;
    // Per-IP fixed windows (quotas on AppState, isolated per test server).
    let limited = |rule: LimitRule, route: Router<AppState>| {
        route
            .route_layer(axum::middleware::from_fn(rate_limit::limit_by_rule))
            .layer(axum::Extension(rule))
    };
    let kyc_submit = limited(
        LimitRule { limiter: state.kyc_limiter.clone(), endpoint: "kyc_submit" },
        Router::new().route("/kyc/applications", post(submit_kyc)),
    );
    let auth = limited(
        LimitRule { limiter: state.login_limiter.clone(), endpoint: "auth_login" },
        Router::new().route("/auth/login", post(login)),
    );
    let refresh = limited(
        LimitRule { limiter: state.refresh_limiter.clone(), endpoint: "auth_refresh" },
        Router::new().route("/auth/refresh", post(refresh)),
    );
    Router::new()
        .route("/health", get(health))
        .route("/events", get(events_ws))
        .route("/auth/me", get(me))
        .route("/auth/logout", post(logout))
        .route("/auth/logout/all", post(logout_all))
        .route("/users", get(list_users).post(create_user))
        .route("/users/:id/:action", post(set_active))
        .route("/auth/password", post(change_password))
        .route("/sites", get(list_sites).post(create_site))
        .route("/sites/:site_id/gates", get(list_gates).post(create_gate))
        .route("/kyc/applications", get(list_kyc))
        .route("/kyc/applications/:id/decide", post(decide_kyc))
        .route("/kyc/applications/:id/press-card", get(press_card))
        .route("/kyc/applications/:id/press-card.png", get(press_card_png))
        .route("/kyc/verify", post(verify_press_card))
        .route("/sites/:site_id/gates/:gate_id/events", post(record_event))
        .route("/sites/:site_id/gates/:gate_id/log", get(gate_log))
        .route("/snapshots", post(upload_snapshot))
        .route("/snapshots/:key", get(download_snapshot))
        .route("/snapshots/:key/share", get(share_snapshot))
        .route("/forensics/embeddings", post(enroll_embedding))
        .route("/forensics/search", post(search_embeddings))
        .route("/sites/:site_id/incidents", post(create_incident).get(list_incidents))
        .route("/sites/:site_id/heatmap", get(site_heatmap))
        .route("/audit", get(list_audit))
        .route("/audit/verify", get(verify_audit))
        .route("/sites/:site_id/audit", get(site_audit))
        .route("/admin/retention/policies", get(list_policies))
        .route("/admin/retention/policies/:entity", post(set_policy))
        .route("/admin/retention/run", post(run_purge))
        .route("/admin/demo/reset", post(reset_demo))
        .route("/sites/:site_id/export", get(export_site))
        .merge(kyc_submit)
        .merge(auth)
        .merge(refresh)
        .layer(axum::Extension(state.hub.clone()))
        .layer(axum::middleware::from_fn(request_id::request_id))
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
