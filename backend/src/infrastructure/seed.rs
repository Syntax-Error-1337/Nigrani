use sqlx::PgPool;

use crate::core::{AppError, AppResult};
use crate::domain::Role;
use crate::infrastructure::auth::hash_password;

/// Seed one login per canonical role (dev only, password `password`).
/// Idempotent: existing usernames are left untouched.
pub async fn seed_users(pool: &PgPool) -> AppResult<()> {
    let accounts: &[(&str, Role)] = &[
        ("superadmin", Role::SuperAdmin),
        ("commander", Role::SiteCommander),
        ("gate", Role::GateOperator),
        ("verifier", Role::VerificationOfficer),
        ("analyst", Role::ForensicAnalyst),
    ];
    for (username, role) in accounts {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)")
            .bind(username)
            .fetch_one(pool)
            .await
            .map_err(AppError::Db)?;
        if exists {
            continue;
        }
        let role_id: uuid::Uuid =
            sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
                .bind(role.as_str())
                .fetch_one(pool)
                .await
                .map_err(AppError::Db)?;
        let password_hash = hash_password("password")?;
        sqlx::query("INSERT INTO users (username, password_hash, role_id) VALUES ($1, $2, $3)")
            .bind(username)
            .bind(password_hash)
            .bind(role_id)
            .execute(pool)
            .await
            .map_err(AppError::Db)?;
        tracing::info!(username, role = %role, "seeded user");
    }
    Ok(())
}
