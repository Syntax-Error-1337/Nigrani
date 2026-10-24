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
        let jti = claims.jti;
        let user = claims.into_user()?;
        // Signature is stateless; validity is not. The session dies with its
        // user row (deleted, deactivated, or wiped by a demo reset) AND with
        // its allowlist row (self-revoked, bulk-revoked, expired). Without
        // this, stale tokens linger and die later as confusing 403s.
        let alive: Option<(bool, bool)> = sqlx::query_as(
            "SELECT u.active, (a.jti IS NOT NULL AND a.revoked_at IS NULL AND a.expires_at > now())
             FROM users u LEFT JOIN access_tokens a ON a.jti = $2 WHERE u.id = $1",
        )
        .bind(user.id)
        .bind(jti)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Db)?;
        match alive {
            Some((true, true)) => Ok(Self(user)),
            Some((true, false)) => Err(AppError::Unauthorized("token revoked".to_owned())),
            _ => Err(AppError::Unauthorized("session no longer valid".to_owned())),
        }
    }
}

/// Permission guard: caller MUST hold `permission` (checked against the DB).
pub async fn require_permission(state: &AppState, user: &User, permission: &str) -> AppResult<()> {
    // SuperAdmin bypass keeps the hot path to a single cheap check.
    if user.role == Role::SuperAdmin {
        return Ok(());
    }
    // Role-level grant cache: one entry per (role, permission), 60s TTL.
    let key = (user.role.as_str().to_owned(), permission.to_owned());
    if let Some(granted) = state.grants.get(&key).await {
        return grant_result(user, permission, granted);
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
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    state.grants.insert(key, granted).await;
    grant_result(user, permission, granted)
}

fn grant_result(user: &User, permission: &str, granted: bool) -> AppResult<()> {
    if granted {
        Ok(())
    } else {
        Err(AppError::Forbidden(format!("role {} lacks permission {permission}", user.role)))
    }
}
