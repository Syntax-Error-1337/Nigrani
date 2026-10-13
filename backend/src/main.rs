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
    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    nigrani::api::serve(state, addr).await?;
    Ok(())
}
