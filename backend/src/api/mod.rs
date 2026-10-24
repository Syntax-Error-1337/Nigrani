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
pub use routes_audit::{chain_hash, verify_chain, anchors_ok};
pub use routes_forensics::escalate_overdue;
mod routes_gate;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use self::events::events_ws;
use self::routes_audit::{anchor_audit, list_audit, site_audit, verify_audit};
use self::routes_demo::reset_demo;
use self::routes_retention::{export_site, list_policies, preview_purge, run_purge, set_policy};
use self::routes_users::{change_password, create_user, set_active, unlock_user};
use self::routes_auth::{
    list_assignable, list_sessions, list_users, login, logout, logout_all, me, refresh,
    revoke_access, revoke_session, totp_disable, totp_enable, totp_setup,
};
use self::routes_forensics::{
    add_incident_link, assign_incident, create_incident, enroll_embedding, export_pack,
    get_surge, list_incident_links, list_incidents, merge_incident, search_embeddings, set_capacity, set_surge,
    site_heatmap, site_trends, transition_incident,
};
use self::routes_gate::{collect_snapshots, download_snapshot, gate_log, record_event, share_snapshot, upload_snapshot};
use self::routes_kyc::{
    decide_kyc, export_crl, list_kyc, press_card, press_card_png, reissue_card, revoke_card,
    submit_kyc, verify_press_card,
};
use self::routes_sites::{
    create_gate, create_site, get_stats, list_gates, list_sites, my_duty, set_gate_archived,
    set_gate_duty, set_site_archived,
};
use self::state::AppState;
use crate::core::AppResult;

pub async fn health() -> &'static str {
    "ok"
}

pub fn router(state: AppState) -> Router {
    use rate_limit::LimitRule;
    // Per-IP fixed windows, cluster-wide via rate_counters (namespaced
    // per instance so test servers stay isolated).
    let state_for_limit = state.clone();
    let limited = |rule: LimitRule, route: Router<AppState>| {
        route
            .route_layer(axum::middleware::from_fn_with_state(
                state_for_limit.clone(),
                rate_limit::limit_by_rule,
            ))
            .layer(axum::Extension(rule))
    };
    let kyc_submit = limited(LimitRule::kyc(), Router::new().route("/kyc/applications", post(submit_kyc)));
    let auth = limited(LimitRule::auth_login(), Router::new().route("/auth/login", post(login)));
    let refresh = limited(LimitRule::auth_refresh(), Router::new().route("/auth/refresh", post(refresh)));
    let snapshots = limited(
        LimitRule::snapshot_upload(),
        Router::new().route("/snapshots", post(upload_snapshot)),
    );
    Router::new()
        .route("/health", get(health))
        .route("/events", get(events_ws))
        .route("/auth/me", get(me))
        .route("/auth/logout", post(logout))
        .route("/auth/logout/all", post(logout_all))
        .route("/auth/sessions", get(list_sessions))
        .route("/auth/sessions/:sid/revoke", post(revoke_session))
        .route("/auth/totp/setup", post(totp_setup))
        .route("/auth/totp/enable", post(totp_enable))
        .route("/auth/totp/disable", post(totp_disable))
        .route("/auth/revoke-access", post(revoke_access))
        .route("/users", get(list_users).post(create_user))
        .route("/users/assignable", get(list_assignable))
        .route("/users/:id/:action", post(set_active))
        .route("/users/:id/unlock", post(unlock_user))
        .route("/auth/password", post(change_password))
        .route("/sites", get(list_sites).post(create_site))
        .route("/sites/:site_id/gates", get(list_gates).post(create_gate))
        .route("/sites/:site_id/archive/:action", post(set_site_archived))
        .route("/sites/:site_id/gates/:gate_id/archive/:action", post(set_gate_archived))
        .route("/sites/:site_id/gates/:gate_id/duty", post(set_gate_duty))
        .route("/my/duty", get(my_duty))
        .route("/stats", get(get_stats))
        .route("/kyc/applications", get(list_kyc))
        .route("/kyc/applications/:id/decide", post(decide_kyc))
        .route("/kyc/applications/:id/revoke-card", post(revoke_card))
        .route("/kyc/applications/:id/reissue", post(reissue_card))
        .route("/kyc/applications/:id/press-card", get(press_card))
        .route("/kyc/applications/:id/press-card.png", get(press_card_png))
        .route("/kyc/verify", post(verify_press_card))
        .route("/kyc/crl", get(export_crl))
        .route("/sites/:site_id/gates/:gate_id/events", post(record_event))
        .route("/sites/:site_id/gates/:gate_id/log", get(gate_log))
        .route("/snapshots/:key", get(download_snapshot))
        .route("/snapshots/:key/share", get(share_snapshot))
        .route("/admin/snapshots/collect", post(collect_snapshots))
        .route("/forensics/embeddings", post(enroll_embedding))
        .route("/sites/:site_id/incidents", post(create_incident).get(list_incidents))
        .route("/forensics/search", post(search_embeddings))
        .route("/sites/:site_id/incidents/:iid/status", post(transition_incident))
        .route("/sites/:site_id/incidents/:iid/merge", post(merge_incident))
        .route("/sites/:site_id/incidents/:iid/pack", get(export_pack))
        .route("/sites/:site_id/incidents/:iid/assign", post(assign_incident))
        .route(
            "/sites/:site_id/incidents/:iid/links",
            post(add_incident_link).get(list_incident_links),
        )
        .route("/sites/:site_id/heatmap", get(site_heatmap))
        .route("/sites/:site_id/trends", get(site_trends))
        .route("/sites/:site_id/surge", get(get_surge).post(set_surge))
        .route("/sites/:site_id/capacity", post(set_capacity))
        .route("/audit", get(list_audit))
        .route("/audit/verify", get(verify_audit))
        .route("/audit/anchor", post(anchor_audit))
        .route("/sites/:site_id/audit", get(site_audit))
        .route("/admin/retention/policies", get(list_policies))
        .route("/admin/retention/policies/:entity", post(set_policy))
        .route("/admin/retention/run", post(run_purge))
        .route("/admin/retention/preview", post(preview_purge))
        .route("/admin/demo/reset", post(reset_demo))
        .route("/sites/:site_id/export", get(export_site))
        .merge(kyc_submit)
        .merge(auth)
        .merge(refresh)
        .merge(snapshots)
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
