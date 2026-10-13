use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::{Role, User};
use crate::infrastructure::auth::{verify_access_token, Claims};

/// Authenticated caller, extracted from `Authorization: Bearer <jwt>`.
#[derive(Debug, Clone)]
pub struct AuthUser(pub User);

impl Claims {
    fn into_user(self) -> AppResult<User> {
        let role =
            Role::from_name(&self.role).ok_or_else(|| AppError::Unauthorized("unknown role".to_owned()))?;
        Ok(User { id: self.sub, username: self.username, role })
    }
}

#[async_trait::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing bearer token".to_owned()))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("malformed authorization header".to_owned()))?;
        let claims = verify_access_token(&state.jwt_secret, token)?;
        Ok(Self(claims.into_user()?))
    }
}

/// Permission guard: caller MUST hold `permission` (checked against the DB).
pub async fn require_permission(pool: &sqlx::PgPool, user: &User, permission: &str) -> AppResult<()> {
    // SuperAdmin bypass keeps the hot path to a single cheap check.
    if user.role == Role::SuperAdmin {
        return Ok(());
    }
    let granted: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM users u
            JOIN roles r ON r.id = u.role_id
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE u.id = $1 AND p.name = $2
        )",
    )
    .bind(user.id)
    .bind(permission)
    .fetch_one(pool)
    .await
    .map_err(AppError::Db)?;
    if granted {
        Ok(())
    } else {
        Err(AppError::Forbidden(format!("role {} lacks permission {permission}", user.role)))
    }
}
