//! Hardware ingest (s-I1): machine-facing crossing webhook for turnstiles,
//! QR scanners, NFC readers. Authenticated by a hashed service token
//! (migration 0027) instead of an operator login; audit actor is the
//! machine (None). Reuses the gate event internals for identical
//! validation, surge evaluation, and hub fan-out.
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use super::state::AppState;
use crate::core::{AppError, AppResult};

#[derive(Debug, Deserialize)]
pub struct HardwareEvent {
    /// Path is the source of truth; the body mirrors it for readability
    /// and is validated for consistency only if machines send it.
    #[serde(default)]
    #[allow(dead_code)]
    pub gate_id: Option<Uuid>,
    pub direction: String,
    pub method: String,
    pub press_card: Option<crate::domain::kyc::PressCard>,
    pub snapshot_key: Option<String>,
}

/// Bearer service-token auth: raw token hashed (sha256 hex) and matched
/// against live `service_tokens`. Marks last use; returns nothing (the
/// machine has no human identity for the audit chain — actor stays NULL).
async fn service_user(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("missing bearer token".to_owned()))?;
    let hash = crate::infrastructure::auth::hex_digest(raw);
    let hit: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, permissions FROM service_tokens
         WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let Some((id, permissions)) = hit else {
        return Err(AppError::Unauthorized("invalid service token".to_owned()));
    };
    // Permission gate (SuperAdmin bypass does not apply to machines).
    let wanted = "entries:write";
    if !permissions.split(',').any(|p| p.trim() == wanted) {
        return Err(AppError::Forbidden(format!("service token lacks {wanted}")));
    }
    sqlx::query("UPDATE service_tokens SET last_used_at = now() WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(AppError::Db)?;
    Ok(permissions)
}

/// Machine-facing crossing ingest. Same denials as the kiosk path
/// (liveness, capacity, snapshot existence); audit actor NULL = machine.
pub async fn ingest_event(
    state: State<AppState>,
    headers: HeaderMap,
    Path((site_id, gate_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<HardwareEvent>,
) -> AppResult<Json<serde_json::Value>> {
    service_user(state.clone(), headers).await?;
    let recorder = super::routes_gate::RecordEvent {
        direction: body.direction.clone(),
        method: body.method.clone(),
        press_card: body.press_card.clone(),
        snapshot_key: body.snapshot_key,
    };
    let log = super::routes_gate::record_crossing(&state, site_id, gate_id, recorder, None).await?;
    Ok(Json(serde_json::json!({ "id": log.id, "recorded_at": log.recorded_at })))
}
