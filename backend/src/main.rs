//! Nigrani core backend: authenticated RBAC API for protest-site management.
use std::net::SocketAddr;

use nigrani::api::state::AppState;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "nigrani=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = AppState::from_env().await?;
    nigrani::infrastructure::seed::seed_users(&state.pool).await?;
    // Active SLA escalation: sweep breached cases every 5 min so escalation
    // no longer depends on someone opening the case list. The lazy read
    // path keeps stamping with the viewing operator as actor.
    {
        let pool = state.pool.clone();
        let hub = state.hub.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                let stamped = nigrani::api::escalate_overdue(&pool, &hub).await;
                if stamped > 0 {
                    tracing::info!(stamped, "sla sweeper escalated overdue incidents");
                }
            }
        });
    }
    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    nigrani::api::serve(state, addr).await?;
    Ok(())
}
