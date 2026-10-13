use std::sync::Arc;

use axum::extract::FromRef;

use crate::infrastructure::db;

/// Cached role grant: (role, permission) -> granted at.
pub type GrantCache = moka::future::Cache<(String, String), bool>;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub jwt_secret: Arc<[u8]>,
    /// None when S3 is unreachable at boot; snapshot endpoints 503.
    pub snapshots: Option<crate::infrastructure::storage::SnapshotStore>,
    pub kyc_limiter: super::rate_limit::Limiter,
    pub login_limiter: super::rate_limit::Limiter,
    pub refresh_limiter: super::rate_limit::Limiter,
    /// Role-grant cache (60s TTL). Revocation propagates within the TTL;
    /// SuperAdmin bypass never consults it.
    pub grants: GrantCache,
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
        let snapshots = match crate::infrastructure::storage::SnapshotStore::from_env().await {
            Ok(store) => Some(store),
            Err(e) => {
                tracing::warn!(error = %e, "snapshot storage unavailable; /snapshots will 503");
                None
            }
        };
        Ok(Self {
            pool,
            jwt_secret: jwt_secret.into_bytes().into(),
            snapshots,
            kyc_limiter: super::rate_limit::Limiter::kyc(),
            login_limiter: super::rate_limit::Limiter::auth_login(),
            refresh_limiter: super::rate_limit::Limiter::auth_refresh(),
            grants: GrantCache::builder().time_to_live(std::time::Duration::from_secs(60)).build(),
        })
    }
}

impl FromRef<AppState> for sqlx::PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}
