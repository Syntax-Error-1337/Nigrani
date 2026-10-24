use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use super::auth::{require_permission, AuthUser};
use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::Role;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub entity: String,
    pub retain_days: i32,
}

fn superadmin(user: &crate::domain::User) -> AppResult<()> {
    if user.role != Role::SuperAdmin {
        return Err(AppError::Forbidden("retention controls are SuperAdmin-only".to_owned()));
    }
    Ok(())
}

pub async fn list_policies(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> AppResult<Json<Vec<RetentionPolicy>>> {
    superadmin(&user)?;
    let rows: Vec<(String, i32)> =
        sqlx::query_as("SELECT entity, retain_days FROM retention_policies ORDER BY entity")
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Db)?;
    Ok(Json(
        rows.into_iter().map(|(entity, retain_days)| RetentionPolicy { entity, retain_days }).collect(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct SetPolicy {
    pub retain_days: i32,
}

pub async fn set_policy(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(entity): Path<String>,
    Json(body): Json<SetPolicy>,
) -> AppResult<Json<RetentionPolicy>> {
    superadmin(&user)?;
    if body.retain_days < 0 || body.retain_days > 3650 {
        return Err(AppError::BadRequest("retain_days must be 0..3650".to_owned()));
    }
    let row: Option<(String, i32)> = sqlx::query_as(
        "UPDATE retention_policies SET retain_days = $1 WHERE entity = $2
         RETURNING entity, retain_days",
    )
    .bind(body.retain_days)
    .bind(&entity)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let Some((entity, retain_days)) = row else {
        return Err(AppError::NotFound("unknown retention entity".to_owned()));
    };
    Ok(Json(RetentionPolicy { entity, retain_days }))
}

#[derive(Debug, Serialize)]
pub struct PurgeReport {
    pub purged: std::collections::HashMap<String, i64>,
    /// S3 keys dereferenced by THIS run's entry_log purge (were referenced
    /// before, unreferenced after). Pre-existing orphans stay the
    /// collector's job — attribution stays clean.
    pub snapshots_dereferenced: i64,
    /// Of those, actually deleted from S3 (0 when storage unconfigured;
    /// the rest age into regular orphans for the next collect).
    pub snapshots_deleted: i64,
    /// S3 delete failures (DB purge already committed; counted, not fatal).
    pub snapshots_delete_failed: i64,
}

/// Purge expired rows per policy, dependency order first (children before
/// parents so FKs never break). The run itself is audit-logged.
pub async fn run_purge(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> AppResult<Json<PurgeReport>> {
    superadmin(&user)?;
    let policies: Vec<(String, i32)> =
        sqlx::query_as("SELECT entity, retain_days FROM retention_policies")
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Db)?;
    let window = |entity: &str| {
        policies.iter().find(|(e, _)| e == entity).map(|(_, d)| *d).unwrap_or(365)
    };
    let mut purged = std::collections::HashMap::new();
    // Children first: links → incidents → embeddings → logs → applications → sessions.
    purged.insert("incident_links".into(), purge_older_than(&state, "incident_links", "added_at", window("incident_links")).await?);
    purged.insert("incidents".into(), purge_older_than(&state, "incidents", "created_at", window("incidents")).await?);
    purged.insert("face_embeddings".into(), purge_older_than(&state, "face_embeddings", "captured_at", window("face_embeddings")).await?);
    let log_window = window("entry_logs");
    let doomed_keys: Vec<String> = if log_window > 0 {
        sqlx::query_scalar(
            "SELECT DISTINCT snapshot_key FROM entry_logs
             WHERE recorded_at < now() - ($1 || ' days')::interval AND snapshot_key <> ''",
        )
        .bind(log_window.to_string())
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Db)?
    } else {
        Vec::new()
    };
    purged.insert("entry_logs".into(), purge_older_than(&state, "entry_logs", "recorded_at", log_window).await?);
    // Post-purge diff: keys this run dereferenced (referenced before, gone now).
    let still_referenced: std::collections::HashSet<String> = sqlx::query_scalar(
        "SELECT DISTINCT snapshot_key FROM entry_logs WHERE snapshot_key <> ''",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?
    .into_iter()
    .collect();
    let dereferenced: Vec<String> =
        doomed_keys.into_iter().filter(|k| !still_referenced.contains(k)).collect();
    let snapshots_dereferenced = dereferenced.len() as i64;
    let (snapshots_deleted, snapshots_delete_failed) = match &state.snapshots {
        Some(store) if !dereferenced.is_empty() => match store.delete_keys(&dereferenced).await {
            Ok(n) => (n, dereferenced.len() as i64 - n),
            Err(e) => {
                tracing::error!(error = %e, "purge snapshot delete failed; keys age into orphans");
                (0, dereferenced.len() as i64)
            }
        },
        _ => (0, 0),
    };
    purged.insert("kyc_applications".into(), purge_older_than(&state, "kyc_applications", "submitted_at", window("kyc_applications")).await?);
    purged.insert(
        "refresh_tokens".into(),
        purge_older_than(&state, "refresh_tokens", "created_at", window("refresh_tokens")).await?,
    );
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "retention.purge",
        "retention",
        None,
        serde_json::json!({
            "purged": purged,
            "snapshots_dereferenced": snapshots_dereferenced,
            "snapshots_deleted": snapshots_deleted,
        }),
    )
    .await;
    Ok(Json(PurgeReport {
        purged,
        snapshots_dereferenced,
        snapshots_deleted,
        snapshots_delete_failed,
    }))
}

/// Purgable tables with their timestamp columns. Single source shared by
/// the real purge and the dry-run preview so predicates cannot drift.
const PURGABLE: &[(&str, &str)] = &[
    ("incident_links", "added_at"),
    ("incidents", "created_at"),
    ("face_embeddings", "captured_at"),
    ("entry_logs", "recorded_at"),
    ("kyc_applications", "submitted_at"),
    ("refresh_tokens", "created_at"),
];

async fn count_older_than(
    state: &AppState,
    table: &str,
    at_column: &str,
    retain_days: i32,
) -> AppResult<i64> {
    if retain_days <= 0 {
        return Ok(0);
    }
    // Table/column are internal constants (not user input); format is safe.
    let n: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {table} WHERE {at_column} < now() - ($1 || ' days')::interval"
    ))
    .bind(retain_days.to_string())
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    Ok(n)
}

/// Dry-run preview: per-entity counts the real purge WOULD delete, plus
/// snapshot keys it would dereference. Read-only (no audit row, no S3).
pub async fn preview_purge(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    superadmin(&user)?;
    let policies: Vec<(String, i32)> =
        sqlx::query_as("SELECT entity, retain_days FROM retention_policies")
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Db)?;
    let window = |entity: &str| {
        policies.iter().find(|(e, _)| e == entity).map(|(_, d)| *d).unwrap_or(365)
    };
    let mut counts = serde_json::Map::new();
    for (table, column) in PURGABLE {
        counts.insert(
            (*table).to_owned(),
            serde_json::json!(count_older_than(&state, table, column, window(table)).await?),
        );
    }
    // s29 diff, minus the deletes: doomed keys not referenced afterwards.
    let log_window = window("entry_logs");
    let doomed: Vec<String> = if log_window > 0 {
        sqlx::query_scalar(
            "SELECT DISTINCT snapshot_key FROM entry_logs
             WHERE recorded_at < now() - ($1 || ' days')::interval AND snapshot_key <> ''",
        )
        .bind(log_window.to_string())
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Db)?
    } else {
        Vec::new()
    };
    let still: std::collections::HashSet<String> = sqlx::query_scalar(
        "SELECT DISTINCT snapshot_key FROM entry_logs WHERE snapshot_key <> ''",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?
    .into_iter()
    .collect();
    let dereferenced = doomed.into_iter().filter(|k| !still.contains(k)).count() as i64;
    Ok(Json(serde_json::json!({
        "dry_run": true,
        "purged": counts,
        "snapshots_dereferenced": dereferenced,
    })))
}

async fn purge_older_than(
    state: &AppState,
    table: &str,
    at_column: &str,
    retain_days: i32,
) -> AppResult<i64> {
    if retain_days <= 0 {
        return Ok(0);
    }
    // Table/column are internal constants (not user input); format is safe.
    let n = sqlx::query(&format!(
        "DELETE FROM {table} WHERE {at_column} < now() - ($1 || ' days')::interval"
    ))
    .bind(retain_days.to_string())
    .execute(&state.pool)
    .await
    .map_err(AppError::Db)?
    .rows_affected() as i64;
    tracing::info!(table, purged = n, "retention purge");
    Ok(n)
}

#[derive(Debug, sqlx::FromRow)]
struct ExportIncident {
    id: uuid::Uuid,
    title: String,
    description: String,
    status: String,
    assigned_to: Option<uuid::Uuid>,
    resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct ExportLink {
    id: uuid::Uuid,
    incident_id: uuid::Uuid,
    kind: String,
    ref_id: String,
    note: String,
    added_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct ExportGate {
    id: uuid::Uuid,
    name: String,
    direction: String,
    archived_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, sqlx::FromRow)]
struct ExportLog {
    id: uuid::Uuid,
    gate_id: uuid::Uuid,
    direction: String,
    method: String,
    recorded_at: chrono::DateTime<chrono::Utc>,
    holder_name: Option<String>,
    holder_org: Option<String>,
}

/// Site data-portability export: gates + recent logs + incidents as JSON.
pub async fn export_site(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<uuid::Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &user, "sites:read").await?;
    let gates: Vec<ExportGate> = sqlx::query_as(
        "SELECT id, name, direction, archived_at FROM gates WHERE site_id = $1 ORDER BY name",
    )
        .bind(site_id)
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Db)?;
    let logs: Vec<ExportLog> = sqlx::query_as(
        "SELECT l.id, l.gate_id, l.direction, l.method, l.recorded_at,
                k.full_name AS holder_name, k.organization AS holder_org
             FROM entry_logs l JOIN gates g ON g.id = l.gate_id
             LEFT JOIN kyc_applications k ON k.id = l.application_id
             WHERE g.site_id = $1 ORDER BY l.recorded_at DESC LIMIT 500",
    )
    .bind(site_id)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let incidents: Vec<ExportIncident> = sqlx::query_as(
        "SELECT id, title, description, status, assigned_to, resolved_at, created_at FROM incidents
             WHERE site_id = $1 ORDER BY created_at DESC LIMIT 200",
    )
    .bind(site_id)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let links: Vec<ExportLink> = sqlx::query_as(
        "SELECT l.id, l.incident_id, l.kind, l.ref_id, l.note, l.added_at
             FROM incident_links l JOIN incidents i ON i.id = l.incident_id
             WHERE i.site_id = $1 ORDER BY l.added_at DESC LIMIT 500",
    )
    .bind(site_id)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    Ok(Json(serde_json::json!({
        "site_id": site_id,
        "exported_at": chrono::Utc::now(),
        "gates": gates.iter().map(|g| serde_json::json!({
            "id": g.id, "name": g.name, "direction": g.direction, "archived_at": g.archived_at,
        })).collect::<Vec<_>>(),
        "entry_logs": logs.iter().map(|r| serde_json::json!({
            "id": r.id, "gate_id": r.gate_id, "direction": r.direction,
            "method": r.method, "recorded_at": r.recorded_at,
            "holder_name": r.holder_name, "holder_org": r.holder_org,
        })).collect::<Vec<_>>(),
        "incidents": incidents.iter().map(|r| serde_json::json!({
            "id": r.id, "title": r.title, "description": r.description, "status": r.status,
            "assigned_to": r.assigned_to, "resolved_at": r.resolved_at, "created_at": r.created_at,
        })).collect::<Vec<_>>(),
        "incident_links": links.iter().map(|r| serde_json::json!({
            "id": r.id, "incident_id": r.incident_id, "kind": r.kind,
            "ref_id": r.ref_id, "note": r.note, "added_at": r.added_at,
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    /// Day to report (UTC calendar day). Defaults to yesterday.
    pub date: Option<String>,
}

fn csv_escape(v: &str) -> String {
    if v.contains(',') || v.contains('"') || v.contains('\n') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_owned()
    }
}

/// Daily crossings report (s-I4): per-gate entry/exit/manual counts for a
/// UTC day as a CSV attachment. Pair with a cron/GET for the daily digest;
/// a scheduler example lives in the README Deploy section.
pub async fn daily_report(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<uuid::Uuid>,
    Query(q): Query<ReportQuery>,
) -> AppResult<impl IntoResponse> {
    require_permission(&state, &user, "sites:read").await?;
    let day = q.date.unwrap_or_else(|| {
        (chrono::Utc::now() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string()
    });
    chrono::NaiveDate::parse_from_str(&day, "%Y-%m-%d")
        .map_err(|_| AppError::BadRequest("date must be YYYY-MM-DD".to_owned()))?;
    let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT g.name,
                count(*) FILTER (WHERE l.direction = 'entry' AND l.method = 'press_card'),
                count(*) FILTER (WHERE l.direction = 'entry' AND l.method = 'manual'),
                count(*) FILTER (WHERE l.direction = 'exit')
         FROM entry_logs l JOIN gates g ON g.id = l.gate_id
         WHERE g.site_id = $1
           AND l.recorded_at >= $2::date
           AND l.recorded_at < $2::date + interval '1 day'
         GROUP BY g.name ORDER BY g.name",
    )
    .bind(site_id)
    .bind(&day)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let mut csv = String::from("gate,card_entries,manual_entries,exits\n");
    for (gate, card, manual, exits) in &rows {
        csv.push_str(&format!(
            "{},{},{},{}\n",
            csv_escape(gate), card, manual, exits
        ));
    }
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "report.daily_downloaded",
        "site",
        Some(site_id),
        serde_json::json!({ "date": day, "gates": rows.len() }),
    )
    .await;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8".to_owned())],
        [(axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"nigrani-{site_id}-{day}.csv\""))],
        csv,
    ))
}
