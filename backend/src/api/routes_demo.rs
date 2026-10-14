use axum::{extract::State, Json};
use serde::Serialize;
use std::collections::HashMap;

use super::auth::AuthUser;
use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::Role;

#[derive(Debug, Serialize)]
pub struct ResetReport {
    pub truncated: HashMap<String, i64>,
}

/// Demo reset: wipe operational data back to a fresh-demo baseline.
/// SuperAdmin-only AND refused when APP_ENV=production (same guard class as
/// seeding — a reset in prod would be catastrophic).
pub async fn reset_demo(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> AppResult<Json<ResetReport>> {
    if user.role != Role::SuperAdmin {
        return Err(AppError::Forbidden("demo reset is SuperAdmin-only".to_owned()));
    }
    if std::env::var("APP_ENV").as_deref() == Ok("production") {
        return Err(AppError::Forbidden(
            "demo reset refused with APP_ENV=production".to_owned(),
        ));
    }
    // Children first; users last (audit.actor SET NULL keeps the trail table
    // droppable — but we truncate audit too, so order is belt-and-braces).
    let tables = [
        "audit_log",
        "face_embeddings",
        "entry_logs",
        "incident_links",
        "incidents",
        "refresh_tokens",
        "gates",
        "kyc_applications",
        "sites",
        "retention_policies",
        "users",
    ];
    let mut truncated = HashMap::new();
    for table in tables {
        // Table names are internal constants (not user input); format is safe.
        let n = sqlx::query(&format!("TRUNCATE {table} RESTART IDENTITY CASCADE"))
            .execute(&state.pool)
            .await
            .map_err(AppError::Db)?
            .rows_affected() as i64;
        truncated.insert(table.to_owned(), n);
    }
    // Re-seed baseline: users (idempotent), Jantar Mantar + Gates 1–4,
    // default retention policies.
    crate::infrastructure::seed::seed_users(&state.pool).await?;
    let site_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO sites (name, location) VALUES ('Jantar Mantar', 'New Delhi')
         RETURNING id",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    for gate in ["Gate 1", "Gate 2", "Gate 3", "Gate 4"] {
        sqlx::query("INSERT INTO gates (site_id, name, direction) VALUES ($1, $2, 'both')")
            .bind(site_id)
            .bind(gate)
            .execute(&state.pool)
            .await
            .map_err(AppError::Db)?;
    }
    for (entity, days) in [
        ("kyc_applications", 365),
        ("face_embeddings", 180),
        ("entry_logs", 365),
        ("refresh_tokens", 30),
        ("audit_log", 0),
        ("incidents", 365),
        ("incident_links", 365),
    ] {
        sqlx::query("INSERT INTO retention_policies (entity, retain_days) VALUES ($1, $2)")
            .bind(entity)
            .bind(days)
            .execute(&state.pool)
            .await
            .map_err(AppError::Db)?;
    }
    // Genesis audit row AFTER truncate so the new trail opens cleanly.
    // Actor is None (system): the operator's own user row was just recreated
    // with a new id, so the old id would violate the actor FK.
    super::routes_audit::record(
        &state.pool,
        None,
        "demo.reset",
        "demo",
        None,
        serde_json::json!({ "truncated": truncated, "by": user.username }),
    )
    .await;
    // The operator's own refresh token survived (users re-seeded, old token
    // rows wiped) — force re-login by revoking nothing (rows are gone).
    Ok(Json(ResetReport { truncated }))
}
