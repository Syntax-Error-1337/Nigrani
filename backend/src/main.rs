//! Nigrani core backend: authenticated RBAC API for protest-site management.
mod api;
mod core;
mod domain;
mod infrastructure;

use std::net::SocketAddr;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use api::state::AppState;

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
    crate::infrastructure::seed::seed_users(&state.pool).await?;
    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    api::serve(state, addr).await?;
    Ok(())
}
