use std::sync::Arc;

use axum::extract::FromRef;

use crate::infrastructure::db;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub jwt_secret: Arc<[u8]>,
    pub kyc_limiter: super::rate_limit::Limiter,
}

impl AppState {
    pub async fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL not set"))?;
        let jwt_secret = match std::env::var("JWT_SECRET") {
            Ok(s) if s.len() >= 32 => s,
            Ok(_) => anyhow::bail!("JWT_SECRET must be at least 32 characters"),
            Err(_) => {
                tracing::warn!("JWT_SECRET unset; using dev fallback (do NOT use in production)");
                "dev-secret-change-me-change-me!!".into()
            }
        };
        let pool = db::connect(&database_url).await?;
        db::run_migrations(&pool).await?;
        Ok(Self {
            pool,
            jwt_secret: jwt_secret.into_bytes().into(),
            kyc_limiter: super::rate_limit::Limiter::kyc(),
        })
    }
}

impl FromRef<AppState> for sqlx::PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}
