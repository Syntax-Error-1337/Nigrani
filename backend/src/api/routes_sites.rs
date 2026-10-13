use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{require_permission, AuthUser};
use super::paging::resolve as resolve_page;
use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::{Gate, GateDirection, Site};

type Ts = chrono::DateTime<chrono::Utc>;

#[derive(Debug, Deserialize)]
pub struct ListFilter {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Substring match on name/location.
    pub q: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSite {
    pub name: String,
    pub location: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateGate {
    pub name: String,
    pub direction: Option<String>,
}

pub async fn list_sites(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Query(filter): Query<ListFilter>,
) -> AppResult<Json<Vec<Site>>> {
    require_permission(&state, &user, "sites:read").await?;
    let (limit, offset) = resolve_page(filter.limit, filter.offset, 50)?;
    let pattern = format!("%{}%", filter.q.as_deref().unwrap_or(""));
    let rows: Vec<(Uuid, String, String, Ts)> = sqlx::query_as(
        "SELECT id, name, location, created_at FROM sites
         WHERE name ILIKE $1 OR location ILIKE $1
         ORDER BY name LIMIT $2 OFFSET $3",
    )
    .bind(pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, name, location, created_at)| Site { id, name, location, created_at })
            .collect(),
    ))
}

pub async fn create_site(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(body): Json<CreateSite>,
) -> AppResult<Json<Site>> {
    require_permission(&state, &user, "sites:write").await?;
    if body.name.trim().is_empty() {
        return Err(AppError::BadRequest("site name required".to_owned()));
    }
    let (id, name, location, created_at): (Uuid, String, String, Ts) = sqlx::query_as(
        "INSERT INTO sites (name, location) VALUES ($1, $2)
         RETURNING id, name, location, created_at",
    )
    .bind(body.name.trim())
    .bind(body.location.as_deref().unwrap_or(""))
    .fetch_one(&state.pool)
    .await
    .map_err(map_constraint)?;
    let site = Site { id, name, location, created_at };
    state.hub.publish(&super::events::HubEvent::Topology { at: site.created_at });
    Ok(Json(site))
}

pub async fn list_gates(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
    Query(filter): Query<ListFilter>,
) -> AppResult<Json<Vec<Gate>>> {
    require_permission(&state, &user, "gates:read").await?;
    let (limit, offset) = resolve_page(filter.limit, filter.offset, 50)?;
    let pattern = format!("%{}%", filter.q.as_deref().unwrap_or(""));
    let rows: Vec<(Uuid, Uuid, String, String, Ts)> = sqlx::query_as(
        "SELECT id, site_id, name, direction, created_at FROM gates
         WHERE site_id = $1 AND name ILIKE $2 ORDER BY name LIMIT $3 OFFSET $4",
    )
    .bind(site_id)
    .bind(pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, gate_site_id, name, direction_str, created_at) in rows {
        let Some(direction) = GateDirection::parse(&direction_str) else {
            continue;
        };
        out.push(Gate { id, site_id: gate_site_id, name, direction, created_at });
    }
    Ok(Json(out))
}

pub async fn create_gate(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
    Json(body): Json<CreateGate>,
) -> AppResult<Json<Gate>> {
    require_permission(&state, &user, "gates:write").await?;
    if body.name.trim().is_empty() {
        return Err(AppError::BadRequest("gate name required".to_owned()));
    }
    let direction = body
        .direction
        .as_deref()
        .map(GateDirection::parse)
        .unwrap_or(Some(GateDirection::Entry))
        .ok_or_else(|| AppError::BadRequest("direction must be entry, exit, or both".to_owned()))?;
    let (id, gate_site_id, name, direction_str, created_at): (Uuid, Uuid, String, String, Ts) =
        sqlx::query_as(
            "INSERT INTO gates (site_id, name, direction) VALUES ($1, $2, $3)
             RETURNING id, site_id, name, direction, created_at",
        )
        .bind(site_id)
        .bind(body.name.trim())
        .bind(direction.as_str())
        .fetch_one(&state.pool)
        .await
        .map_err(map_constraint)?;
    let direction = GateDirection::parse(&direction_str).unwrap_or(GateDirection::Entry);
    let gate = Gate { id, site_id: gate_site_id, name, direction, created_at };
    state.hub.publish(&super::events::HubEvent::Topology { at: gate.created_at });
    Ok(Json(gate))
}

/// Unique violations → 409, FK violations → 404, everything else → 500.
fn map_constraint(e: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db) = &e {
        match db.constraint() {
            Some("sites_name_key") => {
                return AppError::Conflict("site name already exists".to_owned())
            }
            Some("gates_site_id_name_key") => {
                return AppError::Conflict("gate name already exists at this site".to_owned())
            }
            Some("gates_site_id_fkey") => return AppError::NotFound("site not found".to_owned()),
            _ => {}
        }
    }
    AppError::Db(e)
}
