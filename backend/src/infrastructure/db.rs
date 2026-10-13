use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::core::{AppError, AppResult};

pub async fn connect(database_url: &str) -> AppResult<PgPool> {
    PgPoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await
        .map_err(AppError::Db)
}

pub async fn run_migrations(pool: &PgPool) -> AppResult<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("migrations failed: {e}")))
}
