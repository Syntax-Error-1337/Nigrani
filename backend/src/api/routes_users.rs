use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::{require_permission, AuthUser};
use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::Role;
use crate::infrastructure::auth::{hash_password, verify_password};

#[derive(Debug, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub password: String,
    pub role: String,
}

#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: Uuid,
    pub username: String,
    pub role: Role,
    pub active: bool,
    pub failed_logins: i32,
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

pub fn into_view(
    id: Uuid,
    username: String,
    role_name: &str,
    active: bool,
    failed_logins: i32,
    locked_until: Option<chrono::DateTime<chrono::Utc>>,
) -> AppResult<UserView> {
    let role = Role::from_name(role_name)
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("unknown role")))?;
    Ok(UserView { id, username, role, active, failed_logins, locked_until })
}

/// Raw `users` row for operator views (lock state included).
#[derive(Debug, sqlx::FromRow)]
pub struct UserRow {
    id: Uuid,
    username: String,
    role: String,
    active: bool,
    failed_logins: i32,
    locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl UserRow {
    pub fn into_view(self) -> AppResult<UserView> {
        into_view(self.id, self.username, &self.role, self.active, self.failed_logins, self.locked_until)
    }
}

fn valid_username(name: &str) -> bool {
    (3..=32).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn valid_password(pw: &str) -> bool {
    (12..=256).contains(&pw.len())
}

pub async fn create_user(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(body): Json<CreateUser>,
) -> AppResult<Json<UserView>> {
    require_permission(&state, &user, "users:write").await?;
    if !valid_username(&body.username) {
        return Err(AppError::BadRequest(
            "username must be 3-32 chars of [a-z0-9_]".to_owned(),
        ));
    }
    if !valid_password(&body.password) {
        return Err(AppError::BadRequest("password must be 12-256 chars".to_owned()));
    }
    let role = Role::from_name(&body.role)
        .ok_or_else(|| AppError::BadRequest("unknown role".to_owned()))?;
    let role_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
        .bind(role.as_str())
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Db)?;
    let Some(role_id) = role_id else {
        return Err(AppError::Internal(anyhow::anyhow!("role missing")));
    };
    let row: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO users (username, password_hash, role_id) VALUES ($1, $2, $3)
         RETURNING id",
    )
    .bind(&body.username)
    .bind(hash_password(&body.password)?)
    .bind(role_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(db) = &e {
            if db.constraint() == Some("users_username_key") {
                return AppError::Conflict("username taken".to_owned());
            }
        }
        AppError::Db(e)
    })?;
    // Idempotent-by-username would hide mistakes; conflict is explicit.
    let Some((id,)) = row else {
        return Err(AppError::Internal(anyhow::anyhow!("user insert failed")));
    };
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "user.created",
        "user",
        Some(id),
        serde_json::json!({"username": body.username, "role": role.as_str()}),
    )
    .await;
    Ok(Json(UserView {
        id,
        username: body.username,
        role,
        active: true,
        failed_logins: 0,
        locked_until: None,
    }))
}

pub async fn set_active(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path((id, action)): Path<(Uuid, String)>,
) -> AppResult<Json<UserView>> {
    require_permission(&state, &user, "users:write").await?;
    let active = match action.as_str() {
        "deactivate" => false,
        "reactivate" => true,
        _ => return Err(AppError::NotFound("unknown user action".to_owned())),
    };
    if id == user.id {
        return Err(AppError::BadRequest("cannot change your own status".to_owned()));
    }
    let row: Option<UserRow> = sqlx::query_as(
        "UPDATE users SET active = $1 WHERE id = $2
         RETURNING id, username, (SELECT name FROM roles WHERE id = users.role_id) AS role, active,
            failed_logins, locked_until",
    )
        .bind(active)
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Db)?;
    let Some(row) = row else {
        return Err(AppError::NotFound("user not found".to_owned()));
    };
    // Immediate session kill on deactivate.
    if !row.active {
        sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1")
            .bind(row.id)
            .execute(&state.pool)
            .await
            .map_err(AppError::Db)?;
    }
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        if row.active { "user.reactivated" } else { "user.deactivated" },
        "user",
        Some(row.id),
        serde_json::json!({"username": row.username}),
    )
    .await;
    row.into_view().map(Json)
}

/// Operator unlock for a locked account. SuperAdmin-side `users:write`;
/// cannot unlock self (mirrors the set_active self-change rule).
pub async fn unlock_user(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<UserView>> {
    require_permission(&state, &user, "users:write").await?;
    if id == user.id {
        return Err(AppError::BadRequest("cannot change your own status".to_owned()));
    }
    let row: Option<UserRow> = sqlx::query_as(
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1
         RETURNING id, username, (SELECT name FROM roles WHERE id = users.role_id) AS role, active,
            failed_logins, locked_until",
    )
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Db)?;
    let Some(row) = row else {
        return Err(AppError::NotFound("user not found".to_owned()));
    };
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "user.unlocked",
        "user",
        Some(row.id),
        serde_json::json!({"username": row.username}),
    )
    .await;
    row.into_view().map(Json)
}

#[derive(Debug, Deserialize)]
pub struct ChangePassword {
    pub current: String,
    pub new: String,
}

/// Self-service password change; kills all OTHER sessions.
pub async fn change_password(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(body): Json<ChangePassword>,
) -> AppResult<Json<serde_json::Value>> {
    if !valid_password(&body.new) {
        return Err(AppError::BadRequest("password must be 12-256 chars".to_owned()));
    }
    let hash: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, password_hash FROM users WHERE id = $1 AND active")
            .bind(user.id)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Db)?;
    let Some((uid, stored)) = hash else {
        return Err(AppError::Unauthorized("invalid credentials".to_owned()));
    };
    if verify_password(&stored, &body.current).is_err() {
        super::routes_audit::record(
            &state.pool,
            Some(uid),
            "password.change_failed",
            "user",
            Some(uid),
            serde_json::json!({}),
        )
        .await;
        return Err(AppError::Unauthorized("invalid credentials".to_owned()));
    }
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(hash_password(&body.new)?)
        .bind(uid)
        .execute(&state.pool)
        .await
        .map_err(AppError::Db)?;
    let n = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(uid)
    .execute(&state.pool)
    .await
    .map_err(AppError::Db)?
    .rows_affected();
    super::routes_audit::record(
        &state.pool,
        Some(uid),
        "password.changed",
        "user",
        Some(uid),
        serde_json::json!({"sessions_revoked": n}),
    )
    .await;
    Ok(Json(serde_json::json!({ "changed": true })))
}
