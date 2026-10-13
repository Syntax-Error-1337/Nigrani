use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::header::CONTENT_TYPE,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::{require_permission, AuthUser};
use super::routes_kyc::verify_card;
use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::{GateDirection, PressCard};

const MAX_SNAPSHOT_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryLog {
    pub id: Uuid,
    pub gate_id: Uuid,
    pub application_id: Option<Uuid>,
    pub direction: GateDirection,
    pub method: EntryMethod,
    pub snapshot_key: String,
    pub recorded_by: Uuid,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryMethod {
    PressCard,
    Manual,
}

impl EntryMethod {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "press_card" => Some(Self::PressCard),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::PressCard => "press_card",
            Self::Manual => "manual",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct RecordEvent {
    /// `entry` or `exit`.
    pub direction: String,
    /// `press_card` (card verified) or `manual` (operator override).
    pub method: String,
    /// Required when method is `press_card`.
    pub press_card: Option<PressCard>,
    /// Optional snapshot key from `POST /snapshots`.
    pub snapshot_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LogFilter {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Raw `entry_logs` row; converted via [`EntryRow::into_log`].
#[derive(Debug, sqlx::FromRow)]
struct EntryRow {
    id: Uuid,
    gate_id: Uuid,
    application_id: Option<Uuid>,
    direction: String,
    method: String,
    snapshot_key: String,
    recorded_by: Uuid,
    recorded_at: DateTime<Utc>,
}

impl EntryRow {
    fn into_log(self) -> EntryLog {
        EntryLog {
            id: self.id,
            gate_id: self.gate_id,
            application_id: self.application_id,
            direction: if self.direction == "exit" {
                GateDirection::Exit
            } else {
                GateDirection::Entry
            },
            method: if self.method == "manual" {
                EntryMethod::Manual
            } else {
                EntryMethod::PressCard
            },
            snapshot_key: self.snapshot_key,
            recorded_by: self.recorded_by,
            recorded_at: self.recorded_at,
        }
    }
}

/// Hardware-gateway seam: edge agents POST screening events here.
/// Card payloads are HMAC-verified; snapshots are keys from `/snapshots`.
pub async fn record_event(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path((site_id, gate_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RecordEvent>,
) -> AppResult<Json<EntryLog>> {
    require_permission(&state, &user, "entries:write").await?;
    let direction = match body.direction.as_str() {
        "entry" => GateDirection::Entry,
        "exit" => GateDirection::Exit,
        _ => return Err(AppError::BadRequest("direction must be entry or exit".to_owned())),
    };
    let method = EntryMethod::parse(&body.method)
        .ok_or_else(|| AppError::BadRequest("method must be press_card or manual".to_owned()))?;
    // The gate MUST belong to the site in the path (no cross-site logging).
    let gate_site: Option<Uuid> = sqlx::query_scalar("SELECT site_id FROM gates WHERE id = $1")
        .bind(gate_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Db)?;
    if gate_site != Some(site_id) {
        return Err(AppError::NotFound("gate not found at this site".to_owned()));
    }
    let application_id = match (method, body.press_card) {
        (EntryMethod::PressCard, Some(card)) => {
            if !verify_card(&state.jwt_secret, &card) {
                return Err(AppError::Forbidden("press card failed verification".to_owned()));
            }
            Some(card.application_id)
        }
        (EntryMethod::PressCard, None) => {
            return Err(AppError::BadRequest("press_card payload required".to_owned()))
        }
        (EntryMethod::Manual, _) => None,
    };
    let snapshot_key = body.snapshot_key.unwrap_or_default();
    let row: EntryRow = sqlx::query_as(
        "INSERT INTO entry_logs (gate_id, application_id, direction, method, snapshot_key, recorded_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, gate_id, application_id, direction, method, snapshot_key, recorded_by, recorded_at",
    )
        .bind(gate_id)
        .bind(application_id)
        .bind(direction.as_str())
        .bind(method.as_str())
        .bind(snapshot_key)
        .bind(user.id)
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Db)?;
    Ok(Json(row.into_log()))
}

pub async fn gate_log(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path((site_id, gate_id)): Path<(Uuid, Uuid)>,
    Query(filter): Query<LogFilter>,
) -> AppResult<Json<Vec<EntryLog>>> {
    require_permission(&state, &user, "gates:read").await?;
    let (limit, offset) = super::paging::resolve(filter.limit, filter.offset, 50)?;
    let rows: Vec<EntryRow> = sqlx::query_as(
            "SELECT l.id, l.gate_id, l.application_id, l.direction, l.method,
                    l.snapshot_key, l.recorded_by, l.recorded_at
             FROM entry_logs l JOIN gates g ON g.id = l.gate_id
             WHERE l.gate_id = $1 AND g.site_id = $2
             ORDER BY l.recorded_at DESC LIMIT $3 OFFSET $4",
        )
        .bind(gate_id)
        .bind(site_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Db)?;
    Ok(Json(rows.into_iter().map(EntryRow::into_log).collect()))
}

/// Snapshot upload: raw JPEG body (≤5MB), content-addressed by UUID key.
pub async fn upload_snapshot(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    body: Bytes,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &user, "entries:write").await?;
    let Some(store) = &state.snapshots else {
        return Err(AppError::Internal(anyhow::anyhow!("snapshot storage unavailable")));
    };
    if body.len() > MAX_SNAPSHOT_BYTES {
        return Err(AppError::BadRequest("snapshot exceeds 5MB".to_owned()));
    }
    if !is_jpeg(&body) {
        return Err(AppError::BadRequest("snapshot must be a JPEG image".to_owned()));
    }
    let key = format!("{}.jpg", Uuid::new_v4());
    store.put_jpeg(&key, body.to_vec()).await?;
    Ok(Json(serde_json::json!({ "key": key })))
}

/// Share link: presigned S3 URL for direct browser fetch (no API egress).
pub async fn share_snapshot(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(key): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &user, "gates:read").await?;
    if key.contains('/') || key.contains("..") {
        return Err(AppError::BadRequest("invalid snapshot key".to_owned()));
    }
    let Some(store) = &state.snapshots else {
        return Err(AppError::Internal(anyhow::anyhow!("snapshot storage unavailable")));
    };
    Ok(Json(serde_json::json!({ "url": store.share_url(&key).await? })))
}

pub async fn download_snapshot(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(key): Path<String>,
) -> AppResult<Response> {
    require_permission(&state, &user, "gates:read").await?;
    if key.contains('/') || key.contains("..") {
        return Err(AppError::BadRequest("invalid snapshot key".to_owned()));
    }
    let Some(store) = &state.snapshots else {
        return Err(AppError::Internal(anyhow::anyhow!("snapshot storage unavailable")));
    };
    let bytes = store.get(&key).await?;
    Ok(([(CONTENT_TYPE, "image/jpeg")], bytes).into_response())
}

fn is_jpeg(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF
}
