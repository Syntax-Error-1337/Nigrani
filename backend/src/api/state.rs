use std::sync::Arc;

use axum::extract::FromRef;

use crate::infrastructure::db;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub jwt_secret: Arc<[u8]>,
}

impl AppState {
    pub async fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL not set"))?;
        let jwt_secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-change-me".into());
        let pool = db::connect(&database_url).await?;
        db::run_migrations(&pool).await?;
        Ok(Self {
            pool,
            jwt_secret: jwt_secret.into_bytes().into(),
        })
    }
}

impl FromRef<AppState> for sqlx::PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}
