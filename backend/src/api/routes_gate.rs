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
use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::{GateDirection, PressCard};

const MAX_SNAPSHOT_BYTES: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryLog {
    pub id: Uuid,
    pub gate_id: Uuid,
    pub application_id: Option<Uuid>,
    /// Plaintext holder identity (names were never encrypted). None for
    /// manual entries or unlinked/purged applications.
    #[serde(default)]
    pub holder_name: Option<String>,
    #[serde(default)]
    pub holder_org: Option<String>,
    pub direction: GateDirection,
    pub method: EntryMethod,
    pub snapshot_key: String,
    /// NULL when a machine (hardware ingest) recorded the crossing.
    pub recorded_by: Option<Uuid>,
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

/// Raw `entry_logs` row (holder identity LEFT JOINed); converted via
/// [`EntryRow::into_log`].
#[derive(Debug, sqlx::FromRow)]
struct EntryRow {
    id: Uuid,
    gate_id: Uuid,
    application_id: Option<Uuid>,
    holder_name: Option<String>,
    holder_org: Option<String>,
    direction: String,
    method: String,
    snapshot_key: String,
    recorded_by: Option<Uuid>,
    recorded_at: DateTime<Utc>,
}

impl EntryRow {
    fn into_log(self) -> EntryLog {
        EntryLog {
            id: self.id,
            gate_id: self.gate_id,
            application_id: self.application_id,
            holder_name: self.holder_name,
            holder_org: self.holder_org,
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
    record_crossing(&state, site_id, gate_id, body, Some(user.id)).await
}

/// Shared core for the kiosk path (actor = operator) and the hardware
/// ingest webhook (actor = None, machine).
pub async fn record_crossing(
    state: &AppState,
    site_id: Uuid,
    gate_id: Uuid,
    body: RecordEvent,
    actor: Option<Uuid>,
) -> AppResult<Json<EntryLog>> {
    let direction = match body.direction.as_str() {
        "entry" => GateDirection::Entry,
        "exit" => GateDirection::Exit,
        _ => return Err(AppError::BadRequest("direction must be entry or exit".to_owned())),
    };
    let method = EntryMethod::parse(&body.method)
        .ok_or_else(|| AppError::BadRequest("method must be press_card or manual".to_owned()))?;
    // The gate MUST belong to the site in the path (no cross-site logging).
    // Archived gates fail LOUD (410) — crossings must never vanish silently.
    let gate: Option<(Uuid, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as("SELECT site_id, archived_at FROM gates WHERE id = $1")
            .bind(gate_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Db)?;
    let Some((gate_site, gate_archived)) = gate else {
        return Err(AppError::NotFound("gate not found at this site".to_owned()));
    };
    if gate_site != site_id {
        return Err(AppError::NotFound("gate not found at this site".to_owned()));
    }
    if gate_archived.is_some() {
        return Err(AppError::Gone("gate is archived".to_owned()));
    }
    let application_id = match (method, body.press_card) {
        (EntryMethod::PressCard, Some(card)) => {
            let (reason, valid) = super::routes_kyc::card_status(
                &state.pool,
                &state.jwt_secret,
                &card,
            )
            .await;
            if !valid {
                let msg = match reason {
                    "revoked" => "press card revoked",
                    "not_approved" => "press card application not approved",
                    "expired" => "press card expired",
                    "superseded" => "press card superseded",
                    _ => "press card failed verification",
                };
                return Err(AppError::Forbidden(msg.to_owned()));
            }
            Some(card.application_id)
        }
        (EntryMethod::PressCard, None) => {
            return Err(AppError::BadRequest("press_card payload required".to_owned()))
        }
        (EntryMethod::Manual, _) => None,
    };
    // Entry-capacity cap (s-H4): net-present (entries − exits, last 12 h)
    // at or above the site cap refuses the ENTRY with a loud 403 and
    // announces on the hub so every console hears it.
    if direction == GateDirection::Entry {
        let cap: Option<i32> = sqlx::query_scalar(
            "SELECT capacity FROM sites WHERE id = $1",
        )
        .bind(site_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Db)?
        .flatten();
        if let Some(cap) = cap {
            let occupancy: i64 = sqlx::query_scalar(
                "SELECT count(*) FILTER (WHERE l.direction = 'entry')
                       - count(*) FILTER (WHERE l.direction = 'exit')
                 FROM entry_logs l JOIN gates g ON g.id = l.gate_id
                 WHERE g.site_id = $1 AND l.recorded_at > now() - interval '12 hours'",
            )
            .bind(site_id)
            .fetch_one(&state.pool)
            .await
            .map_err(AppError::Db)?;
            if occupancy >= cap as i64 {
                state.hub.publish(&super::events::HubEvent::Capacity {
                    at: chrono::Utc::now(),
                    site_id,
                    occupancy,
                    capacity: cap,
                });
                return Err(AppError::Forbidden(format!(
                    "site at capacity ({occupancy}/{cap}) — entry refused"
                )));
            }
        }
    }
    let snapshot_key = body.snapshot_key.unwrap_or_default();
    if !valid_snapshot_key(&snapshot_key) {
        return Err(AppError::BadRequest("invalid snapshot key".to_owned()));
    }
    // Existence only when storage is wired (tests/dev-without-S3 skip it;
    // format above is always enforced). A crossing citing a missing photo
    // is evidence rot — reject at ingest, not at review.
    if !snapshot_key.is_empty() {
        if let Some(store) = &state.snapshots {
            if !store.exists(&snapshot_key).await? {
                return Err(AppError::NotFound("snapshot not found".to_owned()));
            }
        }
    }
    let inserted: (Uuid,) = sqlx::query_as(
        "INSERT INTO entry_logs (gate_id, application_id, direction, method, snapshot_key, recorded_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id",
    )
        .bind(gate_id)
        .bind(application_id)
        .bind(direction.as_str())
        .bind(method.as_str())
        .bind(snapshot_key)
        .bind(actor)
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Db)?;
    // Re-select with the holder join so POST and GET share one shape.
    let log = load_log(&state.pool, inserted.0)
        .await?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("entry log vanished after insert")))?;
    super::routes_audit::record(
        &state.pool, actor, "gate.event", "entry_log", Some(log.id),
        serde_json::json!({"gate_id": gate_id, "direction": log.direction.as_str(), "method": log.method.as_str()}),
    )
    .await;
    state.hub.publish(&super::events::HubEvent::Crossing {
        at: log.recorded_at,
        site_id,
        gate_id,
        direction: log.direction.as_str().to_owned(),
        method: log.method.as_str().to_owned(),
    });
    // Fire-and-forget surge evaluation (entry crossings only).
    if log.direction.as_str() == "entry" {
        super::routes_forensics::check_surge(&state.pool, &state.hub, site_id, gate_id).await;
    }
    Ok(Json(log))
}

/// One joined row by id (holder identity included, None when unlinked).
async fn load_log(pool: &sqlx::PgPool, id: Uuid) -> AppResult<Option<EntryLog>> {
    let row: Option<EntryRow> = sqlx::query_as(
        "SELECT l.id, l.gate_id, l.application_id, k.full_name AS holder_name,
                k.organization AS holder_org, l.direction, l.method,
                l.snapshot_key, l.recorded_by, l.recorded_at
         FROM entry_logs l LEFT JOIN kyc_applications k ON k.id = l.application_id
         WHERE l.id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Db)?;
    Ok(row.map(EntryRow::into_log))
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
            "SELECT l.id, l.gate_id, l.application_id, k.full_name AS holder_name,
                    k.organization AS holder_org, l.direction, l.method,
                    l.snapshot_key, l.recorded_by, l.recorded_at
             FROM entry_logs l JOIN gates g ON g.id = l.gate_id
             LEFT JOIN kyc_applications k ON k.id = l.application_id
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
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "snapshot.uploaded",
        "snapshot",
        None,
        serde_json::json!({"key": key, "bytes": body.len()}),
    )
    .await;
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

/// Ingest-time snapshot reference check: upload mints `<uuid>.jpg`, so
/// anything else is a client bug (or traversal). Empty = no photo, allowed.
pub fn valid_snapshot_key(key: &str) -> bool {
    if key.is_empty() {
        return true;
    }
    if key.contains('/') || key.contains("..") {
        return false;
    }
    let Some(stem) = key.strip_suffix(".jpg") else {
        return false;
    };
    stem.parse::<Uuid>().is_ok()
}

fn is_jpeg(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF
}

#[derive(Debug, Deserialize)]
pub struct CollectBody {
    /// Default true: report only. False deletes orphans.
    pub dry_run: Option<bool>,
}

/// Orphan collection: bucket keys with no `entry_logs.snapshot_key`
/// reference. SuperAdmin-only; dry-run by default. Reports counts (never
/// key lists — keys stay out of the audit trail).
pub async fn collect_snapshots(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(body): Json<CollectBody>,
) -> AppResult<Json<serde_json::Value>> {
    if user.role != crate::domain::Role::SuperAdmin {
        return Err(AppError::Forbidden("snapshot collection is SuperAdmin-only".to_owned()));
    }
    let Some(store) = &state.snapshots else {
        return Err(AppError::Internal(anyhow::anyhow!("snapshot storage unavailable")));
    };
    let keys = store.list_keys().await?;
    let referenced: std::collections::HashSet<String> = sqlx::query_scalar(
        "SELECT DISTINCT snapshot_key FROM entry_logs WHERE snapshot_key <> ''",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?
    .into_iter()
    .collect();
    let orphans: Vec<String> =
        keys.into_iter().filter(|k| !referenced.contains(k)).collect();
    let dry_run = body.dry_run.unwrap_or(true);
    let deleted = if dry_run { 0 } else { store.delete_keys(&orphans).await? };
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "snapshots.collected",
        "snapshot",
        None,
        serde_json::json!({
            "dry_run": dry_run,
            "orphans": orphans.len(),
            "referenced": referenced.len(),
            "deleted": deleted,
        }),
    )
    .await;
    // Dry-run caps the sample (counts are exact; the list is a preview).
    let sample: Vec<String> = orphans.into_iter().take(500).collect();
    Ok(Json(serde_json::json!({
        "dry_run": dry_run,
        "orphan_count": sample.len(),
        "referenced_count": referenced.len(),
        "deleted": deleted,
        "orphans": if dry_run { sample } else { Vec::<String>::new() },
    })))
}
