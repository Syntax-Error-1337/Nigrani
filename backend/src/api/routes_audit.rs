use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::auth::{require_permission, AuthUser};
use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::Role;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: i64,
    pub at: DateTime<Utc>,
    pub actor: Option<Uuid>,
    pub action: String,
    pub entity: String,
    pub entity_id: Option<Uuid>,
    pub detail: serde_json::Value,
}

/// Append an audit row. Best-effort by design: a logging failure must never
/// fail the mutation it records — it warns loudly instead.
/// The chain hash is computed HERE (single implementation shared with
/// [`verify_chain`]) so writer and verifier can never drift.
pub async fn record(
    pool: &sqlx::PgPool,
    actor: Option<Uuid>,
    action: &str,
    entity: &str,
    entity_id: Option<Uuid>,
    detail: serde_json::Value,
) {
    // One transaction + advisory lock: concurrent writers serialize so the
    // chain never forks (each insert's prev_hash is the true tail).
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(error = %e, action, entity, "audit append FAILED (begin)");
            return;
        }
    };
    if let Err(e) = sqlx::query("SELECT pg_advisory_xact_lock(75431)")
        .execute(&mut *tx)
        .await
    {
        tracing::error!(error = %e, action, entity, "audit append FAILED (lock)");
        return;
    }
    let prev: String =
        sqlx::query_scalar("SELECT COALESCE((SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1), '')")
            .fetch_one(&mut *tx)
            .await
            .unwrap_or_default();
    let at = Utc::now();
    let hash = chain_hash(&prev, at, actor, action, entity, entity_id, &detail);
    let res = sqlx::query(
        "INSERT INTO audit_log (at, actor, action, entity, entity_id, detail, prev_hash, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(at)
    .bind(actor)
    .bind(action)
    .bind(entity)
    .bind(entity_id)
    .bind(detail)
    .bind(&prev)
    .bind(&hash)
    .execute(&mut *tx)
    .await;
    match res {
        Ok(_) => {
            if let Err(e) = tx.commit().await {
                tracing::error!(error = %e, action, entity, "audit append FAILED (commit)");
            }
        }
        Err(e) => tracing::error!(error = %e, action, entity, "audit append FAILED"),
    }
}

/// Canonical preimage: `serde_json::Value` is a bytewise-sorted map by default,
/// so both writer and verifier serialize identically. WARNING: enabling
/// serde_json's `preserve_order` feature would silently fork the chain —
/// external verifiers must serialize with bytewise-sorted keys.
fn chain_hash(
    prev: &str,
    at: DateTime<Utc>,
    actor: Option<Uuid>,
    action: &str,
    entity: &str,
    entity_id: Option<Uuid>,
    detail: &serde_json::Value,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(at.timestamp_micros().to_be_bytes());
    if let Some(a) = actor {
        hasher.update(a.as_bytes());
    }
    hasher.update(action.as_bytes());
    hasher.update(entity.as_bytes());
    if let Some(e) = entity_id {
        hasher.update(e.as_bytes());
    }
    hasher.update(serde_json::to_string(detail).unwrap_or_default().as_bytes());
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Verify the hash chain front-to-back. Reports the first bad seq, if any.
/// Full chain walk (also the pack's verdict source — one implementation so
/// writer and verifier can never drift).
pub async fn verify_chain(pool: &sqlx::PgPool) -> AppResult<(bool, i64, Option<i64>)> {
    let rows: Vec<AuditRowFull> = sqlx::query_as(
        "SELECT seq, at, actor, action, entity, entity_id, detail, prev_hash, hash
         FROM audit_log ORDER BY seq",
    )
        .fetch_all(pool)
        .await
        .map_err(AppError::Db)?;
    let mut prev = String::new();
    let mut checked = 0i64;
    for row in rows {
        if row.prev_hash != prev {
            return Ok((false, checked, Some(row.seq)));
        }
        if chain_hash(&prev, row.at, row.actor, &row.action, &row.entity, row.entity_id, &row.detail)
            != row.hash
        {
            return Ok((false, checked, Some(row.seq)));
        }
        prev = row.hash;
        checked += 1;
    }
    Ok((true, checked, None))
}

/// Raw `audit_log` row (without chain hashes); converted via [`AuditRow::into_entry`].
#[derive(Debug, sqlx::FromRow)]
pub(crate) struct AuditRow {
    seq: i64,
    at: DateTime<Utc>,
    actor: Option<Uuid>,
    action: String,
    entity: String,
    entity_id: Option<Uuid>,
    detail: serde_json::Value,
}

impl AuditRow {
    pub(crate) fn into_entry(self) -> AuditEntry {
        AuditEntry {
            seq: self.seq,
            at: self.at,
            actor: self.actor,
            action: self.action,
            entity: self.entity,
            entity_id: self.entity_id,
            detail: self.detail,
        }
    }
}

/// Full row including chain hashes, for verification.
#[derive(Debug, sqlx::FromRow)]
struct AuditRowFull {
    seq: i64,
    at: DateTime<Utc>,
    actor: Option<Uuid>,
    action: String,
    entity: String,
    entity_id: Option<Uuid>,
    detail: serde_json::Value,
    prev_hash: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
pub struct AuditFilter {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub entity: Option<String>,
}

pub async fn list_audit(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Query(filter): Query<AuditFilter>,
) -> AppResult<Json<Vec<AuditEntry>>> {
    if user.role != Role::SuperAdmin {
        return Err(AppError::Forbidden("audit trail is SuperAdmin-only".to_owned()));
    }
    let (limit, offset) = super::paging::resolve(filter.limit, filter.offset, 50)?;
    let rows: Vec<AuditRow> =         if let Some(entity) = filter.entity.as_deref() {
            sqlx::query_as(
                "SELECT seq, at, actor, action, entity, entity_id, detail
                 FROM audit_log WHERE entity = $1 ORDER BY seq DESC LIMIT $2 OFFSET $3",
            )
            .bind(entity)
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Db)?
        } else {
            sqlx::query_as(
                "SELECT seq, at, actor, action, entity, entity_id, detail
                 FROM audit_log ORDER BY seq DESC LIMIT $1 OFFSET $2",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.pool)
            .await
            .map_err(AppError::Db)?
        };
    Ok(Json(
        rows.into_iter()
            .map(AuditRow::into_entry)
            .collect(),
    ))
}

pub async fn verify_audit(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    if user.role != Role::SuperAdmin {
        return Err(AppError::Forbidden("audit verification is SuperAdmin-only".to_owned()));
    }
    let (ok, checked, first_bad) = verify_chain(&state.pool).await?;
    Ok(Json(serde_json::json!({ "ok": ok, "checked": checked, "first_bad": first_bad })))
}

/// Site-scoped trail for commanders: entries touching this site's entities.
/// Uses entity_id linkage for gates/logs; KYC/incident rows carry no site,
/// so they appear only in the global trail.
pub async fn site_audit(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(site_id): Path<Uuid>,
    Query(filter): Query<AuditFilter>,
) -> AppResult<Json<Vec<AuditEntry>>> {
    require_permission(&state, &user, "sites:read").await?;
    let (limit, offset) = super::paging::resolve(filter.limit, filter.offset, 50)?;
    let rows: Vec<AuditRow> =         sqlx::query_as(
            "SELECT seq, at, actor, action, entity, entity_id, detail
             FROM audit_log
             WHERE entity_id = $1
                OR entity_id IN (SELECT id FROM gates WHERE site_id = $1)
                OR entity_id IN (SELECT l.id FROM entry_logs l JOIN gates g ON g.id = l.gate_id WHERE g.site_id = $1)
                OR entity_id IN (SELECT id FROM incidents WHERE site_id = $1)
             ORDER BY seq DESC LIMIT $2 OFFSET $3",
        )
        .bind(site_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Db)?;
    Ok(Json(
        rows.into_iter()
            .map(AuditRow::into_entry)
            .collect(),
    ))
}
