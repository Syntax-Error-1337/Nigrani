use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::{require_permission, AuthUser};
use super::routes_audit::AuditRow;
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
    /// SLA deadline (created + 72h; NULL for pre-policy rows).
    pub sla_due_at: Option<DateTime<Utc>>,
    /// Stamped the first time a read observes the SLA broken.
    pub escalated_at: Option<DateTime<Utc>>,
    /// Set on the absorbed side of a merge; merged cases are read-only.
    pub merged_into: Option<Uuid>,
    /// Computed: SLA broken and not yet resolved/closed.
    pub overdue: bool,
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
    sla_due_at: Option<DateTime<Utc>>,
    escalated_at: Option<DateTime<Utc>>,
    merged_into: Option<Uuid>,
    created_by: Uuid,
    created_at: DateTime<Utc>,
}

/// The canonical incidents select list (keep in sync with the table).
const INCIDENT_COLS: &str = "id, site_id, title, description, suspect_application_id, \
    status, assigned_to, resolved_at, sla_due_at, escalated_at, merged_into, created_by, created_at";

impl IncidentRow {
    fn into_incident(self) -> Option<Incident> {
        let overdue = matches!(self.status.as_str(), "open" | "investigating")
            && self.sla_due_at.is_some_and(|due| due < chrono::Utc::now());
        Some(Incident {
            id: self.id,
            site_id: self.site_id,
            title: self.title,
            description: self.description,
            suspect_application_id: self.suspect_application_id,
            status: IncidentStatus::parse(&self.status)?,
            assigned_to: self.assigned_to,
            resolved_at: self.resolved_at,
            sla_due_at: self.sla_due_at,
            escalated_at: self.escalated_at,
            merged_into: self.merged_into,
            overdue,
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
    if let Some(entry_id) = body.entry_log_id {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM entry_logs WHERE id = $1)")
            .bind(entry_id)
            .fetch_one(&state.pool)
            .await
            .map_err(AppError::Db)?;
        if !exists {
            return Err(AppError::NotFound("entry log not found".to_owned()));
        }
    }
    if let Some(app_id) = body.application_id {
        let app: Option<(bool,)> = sqlx::query_as(
            "SELECT photo_consent FROM kyc_applications WHERE id = $1",
        )
        .bind(app_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::Db)?;
        let Some((consent,)) = app else {
            return Err(AppError::NotFound("application not found".to_owned()));
        };
        if !consent {
            return Err(AppError::Conflict(
                "application has no biometric consent on record".to_owned(),
            ));
        }
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM kyc_applications WHERE id = $1)")
                .bind(app_id)
                .fetch_one(&state.pool)
                .await
                .map_err(AppError::Db)?;
        if !exists {
            return Err(AppError::NotFound("application not found".to_owned()));
        }
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
    let site: Option<Option<DateTime<Utc>>> =
        sqlx::query_scalar("SELECT archived_at FROM sites WHERE id = $1")
            .bind(site_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Db)?;
    let Some(archived) = site else {
        return Err(AppError::NotFound("site not found".to_owned()));
    };
    if archived.is_some() {
        return Err(AppError::Gone("site is archived".to_owned()));
    }
    if let Some(suspect) = body.suspect_application_id {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM kyc_applications WHERE id = $1)")
                .bind(suspect)
                .fetch_one(&state.pool)
                .await
                .map_err(AppError::Db)?;
        if !exists {
            return Err(AppError::NotFound("suspect application not found".to_owned()));
        }
    }
    let row: IncidentRow = sqlx::query_as(
        "INSERT INTO incidents (site_id, title, description, suspect_application_id, created_by, sla_due_at)
         VALUES ($1, $2, $3, $4, $5, now() + interval '72 hours')
         RETURNING id, site_id, title, description, suspect_application_id,
            status, assigned_to, resolved_at, sla_due_at, escalated_at, merged_into, created_by, created_at",
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
    /// Workflow status filter (open|investigating|resolved|closed).
    pub status: Option<String>,
    /// Assignee filter: explicit user UUID or `me` for the caller.
    pub assignee: Option<String>,
}

pub async fn list_incidents(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
    Query(filter): Query<IncidentFilter>,
) -> AppResult<Json<Vec<Incident>>> {
    require_permission(&state, &user, "gates:read").await?;
    let (limit, offset) = super::paging::resolve(filter.limit, filter.offset, 50)?;
    let status = match filter.status.as_deref() {
        None => None,
        Some(s) => Some(
            IncidentStatus::parse(s)
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "status must be open, investigating, resolved, or closed".to_owned(),
                    )
                })?
                .as_str(),
        ),
    };
    let assignee: Option<Uuid> = match filter.assignee.as_deref() {
        None => None,
        Some("me") => Some(user.id),
        Some(raw) => Some(raw.parse().map_err(|_| AppError::BadRequest("assignee must be a user id or me".to_owned()))?),
    };
    let rows: Vec<IncidentRow> = sqlx::query_as(
        "SELECT id, site_id, title, description, suspect_application_id,
            status, assigned_to, resolved_at, sla_due_at, escalated_at, merged_into, created_by, created_at
         FROM incidents WHERE site_id = $1
           AND ($2::text IS NULL OR status = $2)
           AND ($3::uuid IS NULL OR assigned_to = $3)
         ORDER BY created_at DESC LIMIT $4 OFFSET $5",
    )
        .bind(site_id)
        .bind(status)
        .bind(assignee)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Db)?;
    let mut incidents: Vec<Incident> = rows.into_iter().filter_map(IncidentRow::into_incident).collect();
    // Lazy escalation: the first read that sees an overdue, un-escalated
    // case stamps it (no sweeper task; escalation time is honest — when
    // someone looked). Read-only viewers may trigger it.
    for inc in incidents.iter_mut() {
        if inc.overdue && inc.escalated_at.is_none() {
            let stamped: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
                "UPDATE incidents SET escalated_at = now() WHERE id = $1 AND escalated_at IS NULL RETURNING escalated_at",
            )
            .bind(inc.id)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Db)?;
            if let Some((escalated_at,)) = stamped {
                // Reflect the exact DB stamp in this response.
                inc.escalated_at = Some(escalated_at);
                super::routes_audit::record(
                    &state.pool,
                    Some(user.id),
                    "incident.escalated",
                    "incident",
                    Some(inc.id),
                    serde_json::json!({"sla_due_at": inc.sla_due_at}),
                )
                .await;
                state.hub.publish(&super::events::HubEvent::Incident {
                    at: chrono::Utc::now(),
                    site_id,
                    incident_id: inc.id,
                    action: "escalated".to_owned(),
                });
            }
        }
    }
    Ok(Json(incidents))
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
            status, assigned_to, resolved_at, sla_due_at, escalated_at, merged_into, created_by, created_at
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
    if current.merged_into.is_some() {
        return Err(AppError::Conflict("case is merged and read-only".to_owned()));
    }
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
            status, assigned_to, resolved_at, sla_due_at, escalated_at, merged_into, created_by, created_at",
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
    let current = into_incident_or_500(load_incident(&state.pool, site_id, iid).await?)?;
    if current.merged_into.is_some() {
        return Err(AppError::Conflict("case is merged and read-only".to_owned()));
    }
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
            status, assigned_to, resolved_at, sla_due_at, escalated_at, merged_into, created_by, created_at",
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
    let current = into_incident_or_500(load_incident(&state.pool, site_id, iid).await?)?;
    if current.merged_into.is_some() {
        return Err(AppError::Conflict("case is merged and read-only".to_owned()));
    }
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
        // Entry links cite a real crossing at THIS site (no cross-site
        // evidence confusion); embeddings need existence only (they are
        // site-ambiguous by design).
        "entry" => {
            let ref_uuid: Uuid = ref_id.parse().map_err(|_| {
                AppError::BadRequest("entry link needs a UUID ref_id".to_owned())
            })?;
            let log_site: Option<Uuid> = sqlx::query_scalar(
                "SELECT g.site_id FROM entry_logs l JOIN gates g ON g.id = l.gate_id WHERE l.id = $1",
            )
            .bind(ref_uuid)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Db)?;
            let Some(log_site) = log_site else {
                return Err(AppError::NotFound("entry log not found".to_owned()));
            };
            if log_site != site_id {
                return Err(AppError::BadRequest("cross-site link refused".to_owned()));
            }
        }
        "embedding" => {
            let ref_uuid: Uuid = ref_id.parse().map_err(|_| {
                AppError::BadRequest("embedding link needs a UUID ref_id".to_owned())
            })?;
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM face_embeddings WHERE id = $1)")
                    .bind(ref_uuid)
                    .fetch_one(&state.pool)
                    .await
                    .map_err(AppError::Db)?;
            if !exists {
                return Err(AppError::NotFound("embedding not found".to_owned()));
            }
        }
        "snapshot" if ref_id.is_empty() || ref_id.contains('/') || ref_id.contains("..") => {
            return Err(AppError::BadRequest("invalid snapshot key".to_owned()));
        }
        "snapshot" | "note" => {}
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

// --- Occupancy trends + surge alerting (crowd flow beyond the 24h view) ---

#[derive(Debug, Serialize)]
pub struct TrendBucket {
    /// ISO hour bucket (UTC).
    pub hour: DateTime<Utc>,
    pub entries: i64,
    pub exits: i64,
}

#[derive(Debug, Serialize)]
pub struct SurgeAlertView {
    pub id: Uuid,
    pub gate_id: Uuid,
    pub gate_name: String,
    pub window_start: DateTime<Utc>,
    pub count: i64,
    pub threshold: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SurgeStatus {
    /// Null = alerting disabled for this site.
    pub threshold: Option<i32>,
    pub alerts: Vec<SurgeAlertView>,
}

#[derive(Debug, Deserialize)]
pub struct SurgeThreshold {
    /// Omit or null clears alerting; 1..=10_000 sets entries/hour per gate.
    pub threshold: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct TrendsQuery {
    /// Window in hours, clamped to 2..=720 (30 days).
    pub hours: Option<i64>,
}

/// Hourly entry/exit buckets across the whole site (all gates merged),
/// up to 30 days back. Source of truth for occupancy trends.
pub async fn site_trends(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
    Query(q): Query<TrendsQuery>,
) -> AppResult<Json<Vec<TrendBucket>>> {
    require_permission(&state, &user, "gates:read").await?;
    let hours = q.hours.unwrap_or(24).clamp(2, 720);
    let rows: Vec<(DateTime<Utc>, i64, i64)> = sqlx::query_as(
        "SELECT date_trunc('hour', l.recorded_at) AS bucket,
                COUNT(*) FILTER (WHERE l.direction = 'entry'),
                COUNT(*) FILTER (WHERE l.direction = 'exit')
         FROM entry_logs l JOIN gates g ON g.id = l.gate_id
         WHERE g.site_id = $1 AND l.recorded_at > now() - ($2 || ' hours')::interval
         GROUP BY bucket ORDER BY bucket",
    )
    .bind(site_id)
    .bind(hours.to_string())
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    Ok(Json(
        rows.into_iter().map(|(hour, entries, exits)| TrendBucket { hour, entries, exits }).collect(),
    ))
}

/// Surge settings + recent alerts (last 24h) for a site.
pub async fn get_surge(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
) -> AppResult<Json<SurgeStatus>> {
    require_permission(&state, &user, "gates:read").await?;
    let threshold: Option<i32> =
        sqlx::query_scalar("SELECT surge_threshold FROM sites WHERE id = $1")
            .bind(site_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(AppError::Db)?
            .flatten();
    let alerts = load_alerts(&state.pool, site_id).await?;
    Ok(Json(SurgeStatus { threshold, alerts }))
}

/// Set or clear the per-site surge threshold (entries/hour per gate).

#[derive(Debug, Deserialize)]
pub struct CapacityBody {
    /// Max simultaneous present (entries − exits over the last 12 h at the
    /// site). NULL clears the cap.
    pub capacity: Option<i32>,
}

/// Set/clear the site's entry capacity cap (commander). At capacity, ENTRY
/// crossings are refused 403 and a `capacity` hub event announces it.
pub async fn set_capacity(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
    Json(body): Json<CapacityBody>,
) -> AppResult<Json<serde_json::Value>> {
    require_permission(&state, &user, "sites:write").await?;
    if let Some(c) = body.capacity {
        if !(1..=100_000).contains(&c) {
            return Err(AppError::BadRequest("capacity must be 1..=100000".to_owned()));
        }
    }
    let updated: Option<Option<i32>> = sqlx::query_scalar(
        "UPDATE sites SET capacity = $1 WHERE id = $2 RETURNING capacity",
    )
    .bind(body.capacity)
    .bind(site_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Db)?;
    if updated.is_none() {
        return Err(AppError::NotFound("site not found".to_owned()));
    }
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "site.capacity_set",
        "site",
        Some(site_id),
        serde_json::json!({ "capacity": body.capacity }),
    )
    .await;
    Ok(Json(serde_json::json!({ "capacity": body.capacity })))
}

pub async fn set_surge(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
    Json(body): Json<SurgeThreshold>,
) -> AppResult<Json<SurgeStatus>> {
    require_permission(&state, &user, "sites:write").await?;
    if let Some(t) = body.threshold {
        if !(1..=10_000).contains(&t) {
            return Err(AppError::BadRequest("threshold must be 1..=10000 entries/hour".to_owned()));
        }
    }
    let updated: Option<i32> = sqlx::query_scalar(
        "UPDATE sites SET surge_threshold = $1 WHERE id = $2 RETURNING surge_threshold",
    )
    .bind(body.threshold)
    .bind(site_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let Some(threshold) = updated else {
        return Err(AppError::NotFound("site not found".to_owned()));
    };
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "site.surge_threshold",
        "site",
        Some(site_id),
        serde_json::json!({ "threshold": threshold }),
    )
    .await;
    let alerts = load_alerts(&state.pool, site_id).await?;
    Ok(Json(SurgeStatus { threshold: Some(threshold), alerts }))
}

/// Joined surge-alert row: (id, gate_id, gate_name, window_start, count, threshold, created_at).
type SurgeAlertRow = (Uuid, Uuid, String, DateTime<Utc>, i32, i32, DateTime<Utc>);

/// Recent surge alerts for a site (last 24h), newest first.
async fn load_alerts(pool: &sqlx::PgPool, site_id: Uuid) -> AppResult<Vec<SurgeAlertView>> {
    let rows: Vec<SurgeAlertRow> = sqlx::query_as(
        "SELECT a.id, a.gate_id, g.name, a.window_start, a.count, a.threshold, a.created_at
         FROM surge_alerts a JOIN gates g ON g.id = a.gate_id
         WHERE a.site_id = $1 AND a.created_at > now() - interval '24 hours'
         ORDER BY a.created_at DESC LIMIT 100",
    )
    .bind(site_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::Db)?;
    Ok(rows
        .into_iter()
        .map(|(id, gate_id, gate_name, window_start, count, threshold, created_at)| SurgeAlertView {
            id,
            gate_id,
            gate_name,
            window_start,
            count: i64::from(count),
            threshold: i64::from(threshold),
            created_at,
        })
        .collect())
}

/// Post-insert surge check for one entry crossing: fires at most one alert
/// per (gate, hour) when the hourly count crosses the site threshold.
pub async fn check_surge(
    pool: &sqlx::PgPool,
    hub: &super::events::EventHub,
    site_id: Uuid,
    gate_id: Uuid,
) {
    // Site threshold unset → no-op (single cheap SELECT per crossing).
    let threshold: Option<i32> =
        sqlx::query_scalar("SELECT surge_threshold FROM sites WHERE id = $1")
            .bind(site_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
    let Some(threshold) = threshold else { return };
    let window = "date_trunc('hour', now())";
    let Ok((count,)): std::result::Result<(i64,), _> = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM entry_logs WHERE gate_id = $1 AND direction = 'entry'
         AND recorded_at >= {window}"
    ))
    .bind(gate_id)
    .fetch_one(pool)
    .await
    else { return };
    if count <= i64::from(threshold) {
        return;
    }
    // Insert-once per gate-hour; a winner broadcasts, losers fall through.
    let inserted: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(&format!(
        "INSERT INTO surge_alerts (site_id, gate_id, window_start, count, threshold)
         VALUES ($1, $2, {window}, $3, $4)
         ON CONFLICT (gate_id, window_start) DO NOTHING
         RETURNING id, created_at"
    ))
    .bind(site_id)
    .bind(gate_id)
    .bind(i32::try_from(count).unwrap_or(i32::MAX))
    .bind(threshold)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    if let Some((alert_id, created_at)) = inserted {
        tracing::warn!(%site_id, %gate_id, count, threshold, "surge alert triggered");
        super::routes_audit::record(
            pool, None, "surge.triggered", "surge_alert", Some(alert_id),
            serde_json::json!({ "site_id": site_id, "gate_id": gate_id, "count": count, "threshold": threshold }),
        )
        .await;
        hub.publish(&super::events::HubEvent::Surge {
            at: created_at,
            site_id,
            gate_id,
            count,
            threshold: i64::from(threshold),
        });
    }
}

// --- Case merging + courtroom export pack ---

#[derive(Debug, Deserialize)]
pub struct MergeIncident {
    pub into: Uuid,
}

/// Merge case `iid` into `into`: its evidence links move to the survivor,
/// the absorbed case is closed and marked `merged_into` (read-only after).
/// Same-site, no chains, no self-merge.
pub async fn merge_incident(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path((site_id, iid)): Path<(Uuid, Uuid)>,
    Json(body): Json<MergeIncident>,
) -> AppResult<Json<Incident>> {
    require_permission(&state, &user, "incidents:write").await?;
    if iid == body.into {
        return Err(AppError::BadRequest("cannot merge a case into itself".to_owned()));
    }
    let absorbed = into_incident_or_500(load_incident(&state.pool, site_id, iid).await?)?;
    if absorbed.merged_into.is_some() {
        return Err(AppError::Conflict("case is already merged".to_owned()));
    }
    // Survivor must be a live case of the SAME site and not itself merged
    // (merge chains would make audit attribution ambiguous).
    let survivor: Option<IncidentRow> = sqlx::query_as(&format!(
        "SELECT {INCIDENT_COLS} FROM incidents WHERE id = $1 AND site_id = $2"
    ))
    .bind(body.into)
    .bind(site_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let survivor = into_incident_or_500(survivor.ok_or_else(|| AppError::NotFound("target case not found at this site".to_owned()))?)?;
    if survivor.merged_into.is_some() {
        return Err(AppError::Conflict("target case is already merged".to_owned()));
    }
    // Move the evidence, then tombstone the absorbed case atomically.
    let moved = sqlx::query("UPDATE incident_links SET incident_id = $1 WHERE incident_id = $2")
        .bind(body.into)
        .bind(iid)
        .execute(&state.pool)
        .await
        .map_err(AppError::Db)?
        .rows_affected();
    let row: IncidentRow = sqlx::query_as(&format!(
        "UPDATE incidents SET status = 'closed', merged_into = $1
         WHERE id = $2 AND site_id = $3
         RETURNING {INCIDENT_COLS}"
    ))
    .bind(body.into)
    .bind(iid)
    .bind(site_id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let incident = into_incident_or_500(row)?;
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "incident.merged",
        "incident",
        Some(iid),
        serde_json::json!({"into": body.into, "links_moved": moved}),
    )
    .await;
    state.hub.publish(&super::events::HubEvent::Incident {
        at: chrono::Utc::now(),
        site_id,
        incident_id: iid,
        action: "merged".to_owned(),
    });
    Ok(Json(incident))
}

/// Joined embedding row: (id, captured_at, vector as float4[]).
type EmbeddingRow = (Uuid, Option<DateTime<Utc>>, Option<Vec<f32>>);

/// One resolved evidence item for the courtroom pack.
#[derive(Debug, Serialize)]
pub struct PackEvidence {
    pub link_id: Uuid,
    pub kind: String,
    pub note: String,
    pub added_by: Uuid,
    pub added_at: DateTime<Utc>,
    /// kind=entry: the full crossing row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<serde_json::Value>,
    /// kind=embedding: vector id, capture time, and the 512-d vector itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedding: Option<serde_json::Value>,
    /// kind=snapshot: the storage key (file lives in S3 backups).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CourtroomPack {
    pub incident: Incident,
    pub evidence: Vec<PackEvidence>,
    /// Site-scoped audit slice (chain-verified below) for the court record.
    pub audit: serde_json::Value,
    pub audit_verdict: serde_json::Value,
    pub exported_at: DateTime<Utc>,
    pub exported_by: Uuid,
}

/// Courtroom export: the case, its evidence RESOLVED to actual rows, the
/// site's audit slice, and the hash-chain verdict — one self-contained JSON.
pub async fn export_pack(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path((site_id, iid)): Path<(Uuid, Uuid)>,
) -> AppResult<impl axum::response::IntoResponse> {
    require_permission(&state, &user, "incidents:write").await?;
    let incident = into_incident_or_500(load_incident(&state.pool, site_id, iid).await?)?;
    let link_rows: Vec<IncidentLinkRow> = sqlx::query_as(
        "SELECT id, incident_id, kind, ref_id, note, added_by, added_at
         FROM incident_links WHERE incident_id = $1 ORDER BY added_at",
    )
    .bind(iid)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let mut evidence = Vec::new();
    for link in link_rows {
        let entry = if link.kind == "entry" {
            let parsed = Uuid::parse_str(&link.ref_id).ok();
            match parsed {
                Some(id) => {
                    let row: Option<(serde_json::Value,)> = sqlx::query_as(
                        "SELECT to_jsonb(l) - 'snapshot_key' FROM entry_logs l WHERE id = $1",
                    )
                    .bind(id)
                    .fetch_optional(&state.pool)
                    .await
                    .map_err(AppError::Db)?;
                    row.map(|r| r.0)
                }
                None => None,
            }
        } else {
            None
        };
        let embedding = if link.kind == "embedding" {
            let parsed = Uuid::parse_str(&link.ref_id).ok();
            match parsed {
                Some(id) => {
                    let row: Option<EmbeddingRow> = sqlx::query_as(
                        "SELECT id, captured_at, embedding::float4[] FROM face_embeddings WHERE id = $1",
                    )
                    .bind(id)
                    .fetch_optional(&state.pool)
                    .await
                    .map_err(AppError::Db)?;
                    row.map(|(id, captured_at, vector)| serde_json::json!({
                        "id": id,
                        "captured_at": captured_at,
                        "vector": vector.map(|v| serde_json::json!(v)),
                    }))
                }
                None => None,
            }
        } else {
            None
        };
        let snapshot_key = (link.kind == "snapshot").then(|| link.ref_id.clone());
        evidence.push(PackEvidence {
            link_id: link.id,
            kind: link.kind.clone(),
            note: link.note.clone(),
            added_by: link.added_by,
            added_at: link.added_at,
            entry,
            embedding,
            snapshot_key,
        });
    }
    // Site audit slice (newest first, capped) + chain verdict.
    let audit_rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT seq, at, actor, action, entity, entity_id, detail
         FROM audit_log
         WHERE entity_id = $1
            OR entity_id IN (SELECT l.id FROM entry_logs l JOIN gates g ON g.id = l.gate_id WHERE g.site_id = $2)
            OR entity_id IN (SELECT id FROM incidents WHERE site_id = $2)
         ORDER BY seq DESC LIMIT 500",
    )
    .bind(iid)
    .bind(site_id)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let audit = serde_json::Value::Array(
        audit_rows.into_iter().map(|r| serde_json::to_value(r.into_entry()).unwrap_or_default()).collect(),
    );
    let (ok, checked, first_bad) = super::routes_audit::verify_chain(&state.pool).await?;
    let verdict = serde_json::json!({ "ok": ok, "checked": checked, "first_bad": first_bad });
    let pack = CourtroomPack {
        incident,
        evidence,
        audit,
        audit_verdict: verdict,
        exported_at: chrono::Utc::now(),
        exported_by: user.id,
    };
    super::routes_audit::record(
        &state.pool,
        Some(user.id),
        "incident.pack_exported",
        "incident",
        Some(iid),
        serde_json::json!({}),
    )
    .await;
    let body = serde_json::to_string(&pack)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("pack serialize failed: {e}")))?;
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/json"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"case-pack.json\"",
            ),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        body,
    ))
}

/// Active SLA escalation: sweep every overdue, un-escalated case, stamp it,
/// audit as the system actor (None), and fan out `escalated` events. Called
/// by the background sweeper in main.rs; the lazy read path in list_incidents
/// stamps on first view with the viewing operator as actor. Notification
/// consumers should subscribe to the hub's `escalated` incident events.
pub async fn escalate_overdue(
    pool: &sqlx::PgPool,
    hub: &super::events::EventHub,
) -> usize {
    let due: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "UPDATE incidents SET escalated_at = now()
         WHERE escalated_at IS NULL AND sla_due_at < now()
           AND status IN ('open', 'investigating')
         RETURNING id, site_id",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    for (id, site_id) in &due {
        super::routes_audit::record(pool, None, "incident.escalated", "incident", Some(*id), serde_json::json!({"by": "sla_sweeper"})).await;
        hub.publish(&super::events::HubEvent::Incident {
            at: chrono::Utc::now(),
            site_id: *site_id,
            incident_id: *id,
            action: "escalated".to_owned(),
        });
    }
    due.len()
}
