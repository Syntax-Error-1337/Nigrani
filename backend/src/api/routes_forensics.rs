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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Uuid,
    pub site_id: Option<Uuid>,
    pub title: String,
    pub description: String,
    pub suspect_application_id: Option<Uuid>,
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
    created_by: Uuid,
    created_at: DateTime<Utc>,
}

impl IncidentRow {
    fn into_incident(self) -> Incident {
        Incident {
            id: self.id,
            site_id: self.site_id,
            title: self.title,
            description: self.description,
            suspect_application_id: self.suspect_application_id,
            created_by: self.created_by,
            created_at: self.created_at,
        }
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
         RETURNING id, site_id, title, description, suspect_application_id, created_by, created_at",
    )
        .bind(site_id)
        .bind(body.title.trim())
        .bind(body.description.as_deref().unwrap_or(""))
        .bind(body.suspect_application_id)
        .bind(user.id)
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Db)?;
    let incident = row.into_incident();
    super::routes_audit::record(
        &state.pool, Some(user.id), "incident.created", "incident", Some(incident.id),
        serde_json::json!({"site_id": site_id, "title": incident.title}),
    )
    .await;
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
        "SELECT id, site_id, title, description, suspect_application_id, created_by, created_at
         FROM incidents WHERE site_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
        .bind(site_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Db)?;
    Ok(Json(rows.into_iter().map(IncidentRow::into_incident).collect()))
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
