use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::{require_permission, AuthUser};
use super::state::AppState;
use crate::core::{AppError, AppResult};

pub const EMBEDDING_DIMS: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceEmbedding {
    pub id: Uuid,
    pub entry_log_id: Option<Uuid>,
    pub application_id: Option<Uuid>,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct EnrollEmbedding {
    pub entry_log_id: Option<Uuid>,
    pub application_id: Option<Uuid>,
    pub embedding: Vec<f32>,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub embedding: Vec<f32>,
    pub threshold: Option<f32>,
    pub limit: Option<i64>,
    pub site_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct SearchHit {
    pub id: Uuid,
    pub entry_log_id: Option<Uuid>,
    pub application_id: Option<Uuid>,
    pub distance: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IncidentStatus {
    Open,
    Investigating,
    Resolved,
    Closed,
}

impl IncidentStatus {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "open" => Some(Self::Open),
            "investigating" => Some(Self::Investigating),
            "resolved" => Some(Self::Resolved),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Investigating => "investigating",
            Self::Resolved => "resolved",
            Self::Closed => "closed",
        }
    }

    /// Legal transitions; reopen allowed from closed only.
    fn can_go(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Open, Self::Investigating)
                | (Self::Investigating, Self::Resolved)
                | (Self::Resolved, Self::Closed)
                | (Self::Closed, Self::Investigating)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub site_id: Option<Uuid>,
    pub title: String,
    pub description: String,
    pub suspect_application_id: Option<Uuid>,
    pub status: IncidentStatus,
    pub assigned_to: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Raw `incidents` row; converted via [`IncidentRow::into_incident`].
#[derive(Debug, sqlx::FromRow)]
struct IncidentRow {
    id: Uuid,
    site_id: Option<Uuid>,
    title: String,
    description: String,
    suspect_application_id: Option<Uuid>,
    status: String,
    assigned_to: Option<Uuid>,
    resolved_at: Option<DateTime<Utc>>,
    created_by: Uuid,
    created_at: DateTime<Utc>,
}

impl IncidentRow {
    fn into_incident(self) -> Option<Incident> {
        Some(Incident {
            id: self.id,
            site_id: self.site_id,
            title: self.title,
            description: self.description,
            suspect_application_id: self.suspect_application_id,
            status: IncidentStatus::parse(&self.status)?,
            assigned_to: self.assigned_to,
            resolved_at: self.resolved_at,
            created_by: self.created_by,
            created_at: self.created_at,
        })
    }
}


#[derive(Debug, Deserialize)]
pub struct CreateIncident {
    pub site_id: Option<Uuid>,
    pub title: String,
    pub description: Option<String>,
    pub suspect_application_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct GateHeat {
    pub gate_id: Uuid,
    pub gate_name: String,
    pub entries: i64,
    pub exits: i64,
}

/// Store a caller-supplied 512-d face vector (edge agents extract; we store).
pub async fn enroll_embedding(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(body): Json<EnrollEmbedding>,
) -> AppResult<Json<FaceEmbedding>> {
    require_permission(&state, &user, "forensics:search").await?;
    if body.embedding.len() != EMBEDDING_DIMS {
        return Err(AppError::BadRequest(format!(
            "embedding must have {EMBEDDING_DIMS} dimensions, got {}",
            body.embedding.len()
        )));
    }
    if !body.embedding.iter().all(|v| v.is_finite()) {
        return Err(AppError::BadRequest("embedding must be finite floats".to_owned()));
    }
    let literal = to_vector_literal(&body.embedding);
    let row: (Uuid, Option<Uuid>, Option<Uuid>, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO face_embeddings (entry_log_id, application_id, embedding)
         VALUES ($1, $2, $3::vector) RETURNING id, entry_log_id, application_id, captured_at",
    )
    .bind(body.entry_log_id)
    .bind(body.application_id)
    .bind(&literal)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    Ok(Json(FaceEmbedding {
        id: row.0,
        entry_log_id: row.1,
        application_id: row.2,
        captured_at: row.3,
    }))
}

/// Cosine-distance ranking over stored embeddings, optional site scoping.
pub async fn search_embeddings(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Json(body): Json<SearchQuery>,
) -> AppResult<Json<Vec<SearchHit>>> {
    require_permission(&state, &user, "forensics:search").await?;
    if body.embedding.len() != EMBEDDING_DIMS {
        return Err(AppError::BadRequest(format!(
            "embedding must have {EMBEDDING_DIMS} dimensions, got {}",
            body.embedding.len()
        )));
    }
    let limit = body.limit.unwrap_or(10).clamp(1, 50);
    let threshold = body.threshold.unwrap_or(0.35);
    if !body.embedding.iter().all(|v| v.is_finite()) {
        return Err(AppError::BadRequest("embedding must be finite floats".to_owned()));
    }
    let literal = to_vector_literal(&body.embedding);
    // HNSW index serves the ORDER BY; threshold filters cosine distance.
    let rows: Vec<(Uuid, Option<Uuid>, Option<Uuid>, f64)> = match body.site_id {
        Some(site_id) => {
            sqlx::query_as(
                "SELECT f.id, f.application_id, f.entry_log_id, f.embedding <=> $1::vector AS distance
                 FROM face_embeddings f
                 LEFT JOIN entry_logs l ON l.id = f.entry_log_id
                 LEFT JOIN gates g ON g.id = l.gate_id
                 WHERE (g.site_id = $2 OR f.entry_log_id IS NULL)
                   AND f.embedding <=> $1::vector < $3
                 ORDER BY distance LIMIT $4",
            )
            .bind(&literal)
            .bind(site_id)
            .bind(threshold)
            .bind(limit)
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Db)?
        }
        None => {
            sqlx::query_as(
                "SELECT id, application_id, entry_log_id, embedding <=> $1::vector AS distance
                 FROM face_embeddings
                 WHERE embedding <=> $1::vector < $2
                 ORDER BY distance LIMIT $3",
            )
            .bind(&literal)
            .bind(threshold)
            .bind(limit)
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Db)?
        }
    };
    Ok(Json(
        rows.into_iter()
            .map(|(id, application_id, entry_log_id, distance)| SearchHit {
                id,
                entry_log_id,
                application_id,
                distance: distance as f32,
            })
            .collect(),
    ))
}

/// `[f32; 512]` → pgvector text literal `[0.1,0.2,...]`.
fn to_vector_literal(embedding: &[f32]) -> String {
    let mut out = String::with_capacity(embedding.len() * 8 + 2);
    out.push('[');
    for (i, v) in embedding.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // NaN/Inf would corrupt the column: reject at the boundary.
        out.push_str(&format!("{v}"));
    }
    out.push(']');
    out
}

pub async fn create_incident(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
    Json(body): Json<CreateIncident>,
) -> AppResult<Json<Incident>> {
    require_permission(&state, &user, "incidents:write").await?;
    if body.title.trim().is_empty() {
        return Err(AppError::BadRequest("incident title required".to_owned()));
    }
    // Resolve the path site (body.site_id, when given, MUST agree).
    if let Some(claimed) = body.site_id {
        if claimed != site_id {
            return Err(AppError::BadRequest("site mismatch".to_owned()));
        }
    }
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM sites WHERE id = $1)")
        .bind(site_id)
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Db)?;
    if !exists {
        return Err(AppError::NotFound("site not found".to_owned()));
    }
    let row: IncidentRow = sqlx::query_as(
        "INSERT INTO incidents (site_id, title, description, suspect_application_id, created_by)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, site_id, title, description, suspect_application_id,
            status, assigned_to, resolved_at, created_by, created_at",
    )
        .bind(site_id)
        .bind(body.title.trim())
        .bind(body.description.as_deref().unwrap_or(""))
        .bind(body.suspect_application_id)
        .bind(user.id)
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Db)?;
    let incident = row
        .into_incident()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("bad incident row")))?;
    super::routes_audit::record(
        &state.pool, Some(user.id), "incident.created", "incident", Some(incident.id),
        serde_json::json!({"site_id": site_id, "title": incident.title}),
    )
    .await;
    state.hub.publish(&super::events::HubEvent::Incident {
        at: chrono::Utc::now(),
        site_id,
        incident_id: incident.id,
        action: "created".to_owned(),
    });
    Ok(Json(incident))
}

#[derive(Debug, Deserialize)]
pub struct IncidentFilter {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

pub async fn list_incidents(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
    Query(filter): Query<IncidentFilter>,
) -> AppResult<Json<Vec<Incident>>> {
    require_permission(&state, &user, "gates:read").await?;
    let (limit, offset) = super::paging::resolve(filter.limit, filter.offset, 50)?;
    let rows: Vec<IncidentRow> = sqlx::query_as(
        "SELECT id, site_id, title, description, suspect_application_id,
            status, assigned_to, resolved_at, created_by, created_at
         FROM incidents WHERE site_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
        .bind(site_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Db)?;
    Ok(Json(rows.into_iter().filter_map(IncidentRow::into_incident).collect()))
}
#[derive(Debug, Deserialize)]
pub struct TransitionIncident {
    pub status: String,
}

/// Load an incident scoped to its site (no cross-site mutation).
async fn load_incident(
    pool: &sqlx::PgPool,
    site_id: Uuid,
    iid: Uuid,
) -> AppResult<IncidentRow> {
    let row: Option<IncidentRow> = sqlx::query_as(
        "SELECT id, site_id, title, description, suspect_application_id,
            status, assigned_to, resolved_at, created_by, created_at
         FROM incidents WHERE id = $1 AND site_id = $2",
    )
    .bind(iid)
    .bind(site_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Db)?;
    row.ok_or_else(|| AppError::NotFound("incident not found".to_owned()))
}

fn into_incident_or_500(row: IncidentRow) -> AppResult<Incident> {
    row.into_incident()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("bad incident status in row")))
}

/// Advance an incident along the workflow
/// open → investigating → resolved → closed (+ reopen closed → investigating).
pub async fn transition_incident(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path((site_id, iid)): Path<(Uuid, Uuid)>,
    Json(body): Json<TransitionIncident>,
) -> AppResult<Json<Incident>> {
    require_permission(&state, &user, "incidents:write").await?;
    let next = IncidentStatus::parse(&body.status)
        .ok_or_else(|| AppError::BadRequest("status must be open, investigating, resolved, or closed".to_owned()))?;
    let current = into_incident_or_500(load_incident(&state.pool, site_id, iid).await?)?;
    if current.status == next {
        return Ok(Json(current));
    }
    if !current.status.can_go(next) {
        return Err(AppError::Conflict(format!(
            "illegal transition {} → {}",
            current.status.as_str(),
            next.as_str()
        )));
    }
    // Stamp resolution; reopening clears it so a second resolve re-stamps.
    let row: IncidentRow = sqlx::query_as(
        "UPDATE incidents SET status = $1,
            resolved_at = CASE WHEN $1 = 'resolved' THEN now() WHEN $1 = 'investigating' THEN NULL ELSE resolved_at END
         WHERE id = $2 AND site_id = $3
         RETURNING id, site_id, title, description, suspect_application_id,
            status, assigned_to, resolved_at, created_by, created_at",
    )
    .bind(next.as_str())
    .bind(iid)
    .bind(site_id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let incident = into_incident_or_500(row)?;
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "incident.status",
        "incident",
        Some(iid),
        serde_json::json!({"from": current.status.as_str(), "to": next.as_str()}),
    )
    .await;
    state.hub.publish(&super::events::HubEvent::Incident {
        at: chrono::Utc::now(),
        site_id,
        incident_id: iid,
        action: "status".to_owned(),
    });
    Ok(Json(incident))
}

#[derive(Debug, Deserialize)]
pub struct AssignIncident {
    pub user_id: Uuid,
}

/// Assign a case; the assignee MUST hold `incidents:write` themselves
/// (no dumping cases on gate staff).
pub async fn assign_incident(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path((site_id, iid)): Path<(Uuid, Uuid)>,
    Json(body): Json<AssignIncident>,
) -> AppResult<Json<Incident>> {
    require_permission(&state, &user, "incidents:write").await?;
    load_incident(&state.pool, site_id, iid).await?;
    let target: Option<(Uuid, bool)> =
        sqlx::query_as("SELECT id, active FROM users WHERE id = $1")
            .bind(body.user_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Db)?;
    let Some((target_id, target_active)) = target else {
        return Err(AppError::NotFound("assignee not found".to_owned()));
    };
    if !target_active {
        return Err(AppError::BadRequest("assignee is deactivated".to_owned()));
    }
    let holds: bool = sqlx::query_scalar(
        "SELECT EXISTS (
            SELECT 1 FROM users u
            JOIN roles r ON r.id = u.role_id
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE u.id = $1 AND p.name = 'incidents:write'
        )",
    )
    .bind(target_id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    if !holds {
        return Err(AppError::BadRequest(
            "assignee must hold incidents:write".to_owned(),
        ));
    }
    let row: IncidentRow = sqlx::query_as(
        "UPDATE incidents SET assigned_to = $1 WHERE id = $2 AND site_id = $3
         RETURNING id, site_id, title, description, suspect_application_id,
            status, assigned_to, resolved_at, created_by, created_at",
    )
    .bind(target_id)
    .bind(iid)
    .bind(site_id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "incident.assigned",
        "incident",
        Some(iid),
        serde_json::json!({"assignee": target_id}),
    )
    .await;
    state.hub.publish(&super::events::HubEvent::Incident {
        at: chrono::Utc::now(),
        site_id,
        incident_id: iid,
        action: "assigned".to_owned(),
    });
    into_incident_or_500(row).map(Json)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentLink {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub kind: String,
    pub ref_id: String,
    pub note: String,
    pub added_by: Uuid,
    pub added_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct AddIncidentLink {
    pub kind: String,
    pub ref_id: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct IncidentLinkRow {
    id: Uuid,
    incident_id: Uuid,
    kind: String,
    ref_id: String,
    note: String,
    added_by: Uuid,
    added_at: DateTime<Utc>,
}

impl IncidentLinkRow {
    fn into_link(self) -> IncidentLink {
        IncidentLink {
            id: self.id,
            incident_id: self.incident_id,
            kind: self.kind,
            ref_id: self.ref_id,
            note: self.note,
            added_by: self.added_by,
            added_at: self.added_at,
        }
    }
}

fn valid_link_kind(kind: &str) -> bool {
    matches!(kind, "entry" | "embedding" | "snapshot" | "note")
}

/// Attach evidence to a case: entry-log / embedding ids (UUIDs),
/// snapshot keys (opaque TEXT), or free-text notes.
pub async fn add_incident_link(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path((site_id, iid)): Path<(Uuid, Uuid)>,
    Json(body): Json<AddIncidentLink>,
) -> AppResult<Json<IncidentLink>> {
    require_permission(&state, &user, "incidents:write").await?;
    load_incident(&state.pool, site_id, iid).await?;
    if !valid_link_kind(&body.kind) {
        return Err(AppError::BadRequest(
            "kind must be entry, embedding, snapshot, or note".to_owned(),
        ));
    }
    let ref_id = body.ref_id.as_deref().unwrap_or("").trim().to_owned();
    match body.kind.as_str() {
        "entry" | "embedding" if ref_id.parse::<Uuid>().is_err() => {
            return Err(AppError::BadRequest(format!(
                "{} link needs a UUID ref_id",
                body.kind
            )));
        }
        "snapshot" if ref_id.is_empty() || ref_id.contains('/') || ref_id.contains("..") => {
            return Err(AppError::BadRequest("invalid snapshot key".to_owned()));
        }
        "entry" | "embedding" | "snapshot" | "note" => {}
        _ => {}
    }
    let note = body.note.as_deref().unwrap_or("").trim().to_owned();
    if body.kind == "note" && note.is_empty() {
        return Err(AppError::BadRequest("note link needs note text".to_owned()));
    }
    let row: IncidentLinkRow = sqlx::query_as(
        "INSERT INTO incident_links (incident_id, kind, ref_id, note, added_by)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, incident_id, kind, ref_id, note, added_by, added_at",
    )
    .bind(iid)
    .bind(&body.kind)
    .bind(&ref_id)
    .bind(&note)
    .bind(user.id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "incident.linked",
        "incident",
        Some(iid),
        serde_json::json!({"kind": body.kind, "ref_id": ref_id}),
    )
    .await;
    state.hub.publish(&super::events::HubEvent::Incident {
        at: chrono::Utc::now(),
        site_id,
        incident_id: iid,
        action: "linked".to_owned(),
    });
    Ok(Json(row.into_link()))
}

pub async fn list_incident_links(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path((site_id, iid)): Path<(Uuid, Uuid)>,
) -> AppResult<Json<Vec<IncidentLink>>> {
    require_permission(&state, &user, "gates:read").await?;
    load_incident(&state.pool, site_id, iid).await?;
    let rows: Vec<IncidentLinkRow> = sqlx::query_as(
        "SELECT id, incident_id, kind, ref_id, note, added_by, added_at
         FROM incident_links WHERE incident_id = $1 ORDER BY added_at",
    )
    .bind(iid)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    Ok(Json(
        rows.into_iter().map(IncidentLinkRow::into_link).collect(),
    ))
}

/// Per-gate entry/exit totals for the last 24h (heatmap source).
pub async fn site_heatmap(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
) -> AppResult<Json<Vec<GateHeat>>> {
    require_permission(&state, &user, "gates:read").await?;
    let rows: Vec<(Uuid, String, i64, i64)> = sqlx::query_as(
        "SELECT g.id, g.name,
                COUNT(*) FILTER (WHERE l.direction = 'entry' AND l.recorded_at > now() - interval '24 hours'),
                COUNT(*) FILTER (WHERE l.direction = 'exit' AND l.recorded_at > now() - interval '24 hours')
         FROM gates g LEFT JOIN entry_logs l ON l.gate_id = g.id
         WHERE g.site_id = $1
         GROUP BY g.id, g.name ORDER BY g.name",
    )
    .bind(site_id)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    Ok(Json(
        rows.into_iter()
            .map(|(gate_id, gate_name, entries, exits)| GateHeat {
                gate_id,
                gate_name,
                entries,
                exits,
            })
            .collect(),
    ))
}
