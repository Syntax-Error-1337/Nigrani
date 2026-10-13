use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::{require_permission, AuthUser};
use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::Role;
use crate::infrastructure::auth::{
    hex_digest, issue_access_token, new_refresh_token, refresh_expiry, verify_password,
};

#[derive(Debug, Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: MeResponse,
}

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
}
#[derive(Debug, Deserialize)]
pub struct RefreshBody {
    pub refresh_token: String,
}

/// Runtime-mapped row (no compile-time DB needed unlike `query!`).
#[derive(Debug, sqlx::FromRow)]
struct DbUser {
    id: Uuid,
    username: String,
    password_hash: String,
    role: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginBody>,
) -> AppResult<Json<LoginResponse>> {
    if body.username.is_empty() || body.password.is_empty() {
        return Err(AppError::BadRequest("username and password required".to_owned()));
    }
    if body.username.len() > 64 || body.password.len() > 256 {
        return Err(AppError::BadRequest("username or password too long".to_owned()));
    }
    let row: Option<DbUser> = sqlx::query_as::<_, DbUser>(
        r#"SELECT u.id, u.username, u.password_hash, r.name AS role
           FROM users u JOIN roles r ON r.id = u.role_id
           WHERE u.username = $1"#,
    )
    .bind(&body.username)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let Some(row) = row else {
        super::routes_audit::record(&state.pool, None, "login.failed", "session", None, serde_json::json!({"username": body.username})).await;
        return Err(AppError::Unauthorized("invalid credentials".to_owned()));
    };
    if let Err(e) = verify_password(&row.password_hash, &body.password) {
        super::routes_audit::record(&state.pool, Some(row.id), "login.failed", "session", None, serde_json::json!({"username": body.username})).await;
        return Err(e);
    }
    super::routes_audit::record(&state.pool, Some(row.id), "login.ok", "session", None, serde_json::json!({"username": body.username})).await;
    let role = Role::from_name(&row.role)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("unknown role {}", row.role)))?;
    let access_token = issue_access_token(&state.jwt_secret, row.id, &row.username, role)?;
    let (refresh_token, stored_hash) = new_refresh_token();
    sqlx::query("INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)")
        .bind(row.id)
        .bind(&stored_hash)
        .bind(refresh_expiry())
        .execute(&state.pool)
        .await
        .map_err(AppError::Db)?;
    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        user: MeResponse { id: row.id, username: row.username, role },
    }))
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshBody>,
) -> AppResult<Json<LoginResponse>> {
    let stored = hex_digest(&body.refresh_token);
    let rec: Option<(Uuid, chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as("SELECT user_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = $1")
            .bind(&stored)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Db)?;
    let Some((user_id, expires_at, revoked_at)) = rec else {
        return Err(AppError::Unauthorized("invalid refresh token".to_owned()));
    };
    if expires_at < chrono::Utc::now() {
        return Err(AppError::Unauthorized("refresh token expired".to_owned()));
    }
    // Reuse detection: a revoked token presented again means the family is
    // compromised — burn every live token for that user and force re-login.
    if revoked_at.is_some() {
        sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
            .bind(user_id)
            .execute(&state.pool)
            .await
            .map_err(AppError::Db)?;
        tracing::warn!(%user_id, "refresh token reuse detected; session family revoked");
        return Err(AppError::Unauthorized("refresh token reused".to_owned()));
    }
    // Rotation: revoke the presented token, issue a fresh pair.
    sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1")
        .bind(&stored)
        .execute(&state.pool)
        .await
        .map_err(AppError::Db)?;
    let row: DbUser = sqlx::query_as::<_, DbUser>(
        r#"SELECT u.id, u.username, u.password_hash, r.name AS role
           FROM users u JOIN roles r ON r.id = u.role_id
           WHERE u.id = $1"#,
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let role = Role::from_name(&row.role)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("unknown role {}", row.role)))?;
    let access_token = issue_access_token(&state.jwt_secret, row.id, &row.username, role)?;
    let (refresh_token, new_hash) = new_refresh_token();
    sqlx::query("INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)")
        .bind(row.id)
        .bind(&new_hash)
        .bind(refresh_expiry())
        .execute(&state.pool)
        .await
        .map_err(AppError::Db)?;
    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        user: MeResponse { id: row.id, username: row.username, role },
    }))
}

/// Logout: revoke the presented refresh token. Idempotent — unknown tokens
/// still return 200 so retries are safe.
pub async fn logout(
    State(state): State<AppState>,
    Json(body): Json<RefreshBody>,
) -> AppResult<Json<serde_json::Value>> {
    let stored = hex_digest(&body.refresh_token);
    sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL")
        .bind(&stored)
        .execute(&state.pool)
        .await
        .map_err(AppError::Db)?;
    Ok(Json(serde_json::json!({ "logged_out": true })))
}

/// Logout-all: revoke every live refresh token for the caller (kills sibling
/// sessions). Access JWTs remain valid until their 15-min expiry.
pub async fn logout_all(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let n = sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(user.id)
        .execute(&state.pool)
        .await
        .map_err(AppError::Db)?
        .rows_affected();
    tracing::info!(user_id = %user.id, revoked = n, "all sessions revoked");
    Ok(Json(serde_json::json!({ "logged_out": true, "sessions_revoked": n })))
}

pub async fn me(AuthUser(user): AuthUser) -> Json<MeResponse> {
    Json(MeResponse { id: user.id, username: user.username, role: user.role })
}

/// Permission-gated endpoint: only roles with `users:read` pass.
pub async fn list_users(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> AppResult<Json<Vec<MeResponse>>> {
    require_permission(&state, &user, "users:read").await?;
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        r#"SELECT u.id, u.username, r.name AS role
           FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.username"#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, username, role_name) in rows {
        let Some(role) = Role::from_name(&role_name) else { continue };
        out.push(MeResponse { id, username, role });
    }
    Ok(Json(out))
}
