use axum::{
    extract::{Path, Query, State},
    Json,
};
use base64::Engine as _;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{require_permission, AuthUser};
use super::state::AppState;
use crate::core::{AppError, AppResult};
use crate::domain::{DocumentType, KycApplication, KycStatus, PressCard};

type HmacSha256 = Hmac<Sha256>;
type Ts = chrono::DateTime<chrono::Utc>;

#[derive(Debug, Deserialize)]
pub struct SubmitKyc {
    pub full_name: String,
    pub organization: Option<String>,
    pub document_type: String,
    pub document_number: String,
    pub photo_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KycFilter {
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DecideKyc {
    /// `approved` or `rejected`.
    pub decision: String,
    pub note: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct KycRow {
    id: Uuid,
    full_name: String,
    organization: String,
    document_type: String,
    document_number: String,
    photo_url: String,
    status: String,
    submitted_at: Ts,
    decided_at: Option<Ts>,
    decided_by: Option<Uuid>,
    decision_note: String,
}

fn to_application(row: KycRow) -> Option<KycApplication> {
    Some(KycApplication {
        id: row.id,
        full_name: row.full_name,
        organization: row.organization,
        document_type: DocumentType::parse(&row.document_type)?,
        document_number: row.document_number,
        photo_url: row.photo_url,
        status: KycStatus::parse(&row.status)?,
        submitted_at: row.submitted_at,
        decided_at: row.decided_at,
        decided_by: row.decided_by,
        decision_note: row.decision_note,
    })
}

const ROW_COLS: &str = "id, full_name, organization, document_type, document_number, \
    photo_url, status, submitted_at, decided_at, decided_by, decision_note";

/// Public endpoint: journalists submit identity documents for review.
/// No auth by design (pre-registration portal); rate limiting lands in s3.
pub async fn submit_kyc(
    State(state): State<AppState>,
    Json(body): Json<SubmitKyc>,
) -> AppResult<Json<KycApplication>> {
    if body.full_name.trim().is_empty() {
        return Err(AppError::BadRequest("full name required".to_owned()));
    }
    if body.document_number.trim().is_empty() {
        return Err(AppError::BadRequest("document number required".to_owned()));
    }
    let document_type = DocumentType::parse(&body.document_type).ok_or_else(|| {
        AppError::BadRequest("document_type must be aadhaar, pan, or press_id".to_owned())
    })?;
    let row: KycRow = sqlx::query_as(&format!(
        "INSERT INTO kyc_applications (full_name, organization, document_type, document_number, photo_url)
         VALUES ($1, $2, $3, $4, $5) RETURNING {ROW_COLS}"
    ))
    .bind(body.full_name.trim())
    .bind(body.organization.as_deref().unwrap_or(""))
    .bind(document_type.as_str())
    .bind(body.document_number.trim())
    .bind(body.photo_url.as_deref().unwrap_or(""))
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    Ok(Json(to_application(row).ok_or_else(|| AppError::Internal(anyhow::anyhow!("bad kyc row")))?))
}

/// Reviewer queue; optional `?status=pending|approved|rejected`.
pub async fn list_kyc(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Query(filter): Query<KycFilter>,
) -> AppResult<Json<Vec<KycApplication>>> {
    require_permission(&state.pool, &user, "kyc:review").await?;
    let status = filter.status.as_deref().unwrap_or("pending");
    if KycStatus::parse(status).is_none() {
        return Err(AppError::BadRequest("status must be pending, approved, or rejected".to_owned()));
    }
    let rows: Vec<KycRow> = sqlx::query_as(&format!(
        "SELECT {ROW_COLS} FROM kyc_applications WHERE status = $1 ORDER BY submitted_at"
    ))
    .bind(status)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    Ok(Json(rows.into_iter().filter_map(to_application).collect()))
}

/// Approve or reject a pending application. Decided rows are immutable.
pub async fn decide_kyc(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(application_id): Path<Uuid>,
    Json(body): Json<DecideKyc>,
) -> AppResult<Json<KycApplication>> {
    require_permission(&state.pool, &user, "kyc:review").await?;
    let status = match body.decision.as_str() {
        "approved" => KycStatus::Approved,
        "rejected" => KycStatus::Rejected,
        _ => return Err(AppError::BadRequest("decision must be approved or rejected".to_owned())),
    };
    let row: Option<KycRow> = sqlx::query_as(&format!(
        "UPDATE kyc_applications SET status = $1, decided_at = now(), decided_by = $2, decision_note = $3
         WHERE id = $4 AND status = 'pending' RETURNING {ROW_COLS}"
    ))
    .bind(status.as_str())
    .bind(user.id)
    .bind(body.note.as_deref().unwrap_or(""))
    .bind(application_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let Some(row) = row else {
        // Distinguish "never existed" from "already decided" for a clear error.
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM kyc_applications WHERE id = $1)")
            .bind(application_id)
            .fetch_one(&state.pool)
            .await
            .map_err(AppError::Db)?;
        return Err(if exists {
            AppError::Conflict("application already decided".to_owned())
        } else {
            AppError::NotFound("application not found".to_owned())
        });
    };
    Ok(Json(to_application(row).ok_or_else(|| AppError::Internal(anyhow::anyhow!("bad kyc row")))?))
}

/// Signed press card for an approved application (QR payload for gate scans).
pub async fn press_card(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(application_id): Path<Uuid>,
) -> AppResult<Json<PressCard>> {
    require_permission(&state.pool, &user, "kyc:review").await?;
    let row: Option<KycRow> = sqlx::query_as(&format!(
        "SELECT {ROW_COLS} FROM kyc_applications WHERE id = $1"
    ))
    .bind(application_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let Some(row) = row else {
        return Err(AppError::NotFound("application not found".to_owned()));
    };
    if row.status != KycStatus::Approved.as_str() {
        return Err(AppError::Conflict("press card requires an approved application".to_owned()));
    }
    let card = sign_card(&state.jwt_secret, &row);
    Ok(Json(card))
}

fn sign_card(secret: &[u8], row: &KycRow) -> PressCard {
    let issued_at = Utc::now();
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(row.id.as_bytes());
    mac.update(row.full_name.as_bytes());
    mac.update(row.organization.as_bytes());
    mac.update(issued_at.timestamp().to_be_bytes().as_ref());
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(mac.finalize().into_bytes());
    PressCard {
        application_id: row.id,
        full_name: row.full_name.clone(),
        organization: row.organization.clone(),
        issued_at,
        signature,
    }
}

/// Gate-side verification of a presented press card (HMAC recompute).
/// Any authenticated gate role can scan; no `kyc:review` needed.
pub async fn verify_press_card(
    State(state): State<AppState>,
    AuthUser(_user): AuthUser,
    Json(card): Json<PressCard>,
) -> AppResult<Json<serde_json::Value>> {
    let valid = verify_card(&state.jwt_secret, &card);
    Ok(Json(serde_json::json!({ "valid": valid, "application_id": card.application_id })))
}

fn verify_card(secret: &[u8], card: &PressCard) -> bool {
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(card.application_id.as_bytes());
    mac.update(card.full_name.as_bytes());
    mac.update(card.organization.as_bytes());
    mac.update(card.issued_at.timestamp().to_be_bytes().as_ref());
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(mac.finalize().into_bytes());
    // Constant-time compare without a new dep: fixed-length base64, fold diffs.
    expected.len() == card.signature.len()
        && expected
            .bytes()
            .zip(card.signature.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}
