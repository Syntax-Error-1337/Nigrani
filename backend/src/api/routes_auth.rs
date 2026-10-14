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
    /// Owner-visible lock state (own row only — no oracle for others).
    /// None when never locked or the lock has expired.
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
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
    active: bool,
    failed_logins: i32,
    locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Strikes before a lock engages; lock length after the final strike.
pub const LOCKOUT_STRIKES: i32 = 5;
pub const LOCKOUT_MINUTES: i64 = 15;

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
        r#"SELECT u.id, u.username, u.password_hash, r.name AS role, u.active,
                  u.failed_logins, u.locked_until
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
    // Inactive accounts fail exactly like bad credentials (no oracle).
    if !row.active {
        super::routes_audit::record(&state.pool, Some(row.id), "login.failed", "session", None, serde_json::json!({"username": body.username, "inactive": true})).await;
        return Err(AppError::Unauthorized("invalid credentials".to_owned()));
    }
    // Locked accounts fail identically too: the lock is owner-visible via
    // `GET /auth/me`, never via the login response.
    if row.locked_until.is_some_and(|until| until > chrono::Utc::now()) {
        super::routes_audit::record(&state.pool, Some(row.id), "login.locked", "session", None, serde_json::json!({"username": body.username})).await;
        return Err(AppError::Unauthorized("invalid credentials".to_owned()));
    }
    if let Err(e) = verify_password(&row.password_hash, &body.password) {
        let strikes = row.failed_logins + 1;
        if strikes >= LOCKOUT_STRIKES {
            sqlx::query(
                "UPDATE users SET failed_logins = $1, locked_until = now() + ($2 || ' minutes')::interval WHERE id = $3",
            )
            .bind(strikes)
            .bind(LOCKOUT_MINUTES.to_string())
            .bind(row.id)
            .execute(&state.pool)
            .await
            .map_err(AppError::Db)?;
            // Immediate session kill (mirrors deactivate): outstanding
            // access JWTs run to their <=15-min expiry, but rotation ends.
            sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL")
                .bind(row.id)
                .execute(&state.pool)
                .await
                .map_err(AppError::Db)?;
            super::routes_audit::record(&state.pool, Some(row.id), "login.locked", "session", None, serde_json::json!({"username": body.username, "strikes": strikes})).await;
        } else {
            sqlx::query("UPDATE users SET failed_logins = $1 WHERE id = $2")
                .bind(strikes)
                .bind(row.id)
                .execute(&state.pool)
                .await
                .map_err(AppError::Db)?;
            super::routes_audit::record(&state.pool, Some(row.id), "login.failed", "session", None, serde_json::json!({"username": body.username})).await;
        }
        return Err(e);
    }
    // Success clears the strike counter.
    if row.failed_logins > 0 {
        sqlx::query("UPDATE users SET failed_logins = 0 WHERE id = $1")
            .bind(row.id)
            .execute(&state.pool)
            .await
            .map_err(AppError::Db)?;
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
        user: MeResponse { id: row.id, username: row.username, role, locked_until: None },
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
        r#"SELECT u.id, u.username, u.password_hash, r.name AS role, u.active,
                  u.failed_logins, u.locked_until
           FROM users u JOIN roles r ON r.id = u.role_id
           WHERE u.id = $1"#,
    )
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    if !row.active {
        return Err(AppError::Unauthorized("refresh token expired".to_owned()));
    }
    // Locked users cannot rotate (same indistinguishable body; the lock is
    // owner-visible via /auth/me, never via auth responses).
    if row.locked_until.is_some_and(|until| until > chrono::Utc::now()) {
        return Err(AppError::Unauthorized("refresh token expired".to_owned()));
    }
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
        user: MeResponse { id: row.id, username: row.username, role, locked_until: None },
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

pub async fn me(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> AppResult<Json<MeResponse>> {
    let locked: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT locked_until FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Db)?
            .flatten()
            .filter(|until| *until > chrono::Utc::now());
    Ok(Json(MeResponse {
        id: user.id,
        username: user.username,
        role: user.role,
        locked_until: locked,
    }))
}

/// Permission-gated endpoint: only roles with `users:read` pass.
pub async fn list_users(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> AppResult<Json<Vec<super::routes_users::UserView>>> {
    require_permission(&state, &user, "users:read").await?;
    let rows: Vec<super::routes_users::UserRow> = sqlx::query_as(
        r#"SELECT u.id, u.username, r.name AS role, u.active, u.failed_logins, u.locked_until
           FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.username"#,
    )
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Db)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if let Ok(view) = row.into_view() {
            out.push(view);
        }
    }
    Ok(Json(out))
}
