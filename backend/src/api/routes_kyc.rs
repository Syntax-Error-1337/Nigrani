use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
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
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Substring match on name/organization (plaintext columns only —
    /// encrypted document numbers are not searchable; see docs).
    pub q: Option<String>,
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
    doc_fingerprint: String,
}

fn to_application(
    crypto: &crate::infrastructure::crypto::TemplateCrypto,
    row: KycRow,
) -> AppResult<Option<KycApplication>> {
    // Per-row isolation: one undecryptable row (foreign key, corruption)
    // degrades to redacted placeholders instead of failing the whole list.
    // The row stays visible so reviewers notice and re-request documents.
    const REDACTED: &str = "[undecryptable — re-request documents]";
    let document_number = crypto.decrypt(&row.document_number).unwrap_or_else(|e| {
        tracing::error!(id = %row.id, error = %e, "kyc row undecryptable");
        REDACTED.to_owned()
    });
    let photo_url = crypto.decrypt_opt(&row.photo_url).unwrap_or_else(|e| {
        tracing::error!(id = %row.id, error = %e, "kyc photo undecryptable");
        REDACTED.to_owned()
    });
    Ok(Some(KycApplication {
        id: row.id,
        full_name: row.full_name,
        organization: row.organization,
        document_type: DocumentType::parse(&row.document_type)
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("bad kyc row")))?,
        document_number,
        photo_url,
        status: KycStatus::parse(&row.status)
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("bad kyc row")))?,
        submitted_at: row.submitted_at,
        decided_at: row.decided_at,
        decided_by: row.decided_by,
        decision_note: row.decision_note,
        prior_decisions: 0,
    }))
}

const ROW_COLS: &str = "id, full_name, organization, document_type, document_number, \
    photo_url, status, submitted_at, decided_at, decided_by, decision_note, doc_fingerprint";

/// Canonical blind-index input: `document_type|NUMBER`, trimmed + uppercased.
/// PAN/Aadhaar are case-insensitive identifiers; `pan| abc123` == `pan|ABC123`.
pub fn normalize_document(document_type: &str, document_number: &str) -> String {
    format!("{document_type}|{}", document_number.trim().to_uppercase())
}

/// Count of decided (non-pending) rows sharing a fingerprint, excluding one id.
/// Indexed equality; reviewers see repeat applicants at a glance.
async fn prior_count(
    pool: &sqlx::PgPool,
    fingerprint: &str,
    exclude: Uuid,
) -> AppResult<i64> {
    if fingerprint.is_empty() {
        return Ok(0);
    }
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM kyc_applications
         WHERE doc_fingerprint = $1 AND status <> 'pending' AND id <> $2",
    )
    .bind(fingerprint)
    .bind(exclude)
    .fetch_one(pool)
    .await
    .map_err(AppError::Db)
}

/// Fail-closed accessor: without BIOMETRIC_KEY no PII may be written or read.
fn crypto(state: &AppState) -> AppResult<crate::infrastructure::crypto::TemplateCrypto> {
    state.crypto.clone().ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("encryption unavailable; set BIOMETRIC_KEY"))
    })
}

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
    let crypto = crypto(&state)?;
    let fingerprint =
        crypto.fingerprint(&normalize_document(document_type.as_str(), body.document_number.trim()));
    // A live pending row for this document blocks resubmission (queue spam).
    // Decided rows don't block: re-application after rejection is legitimate
    // (and surfaces via `prior_decisions` instead).
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM kyc_applications WHERE doc_fingerprint = $1 AND status = 'pending')",
    )
    .bind(&fingerprint)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    if pending {
        super::routes_audit::record(
            &state.pool,
            None,
            "kyc.duplicate_blocked",
            "kyc_application",
            None,
            serde_json::json!({"fingerprint_prefix": &fingerprint[..8.min(fingerprint.len())]}),
        )
        .await;
        return Err(AppError::Conflict(
            "a pending application already exists for this document".to_owned(),
        ));
    }
    let row: KycRow = sqlx::query_as(&format!(
        "INSERT INTO kyc_applications (full_name, organization, document_type, document_number, photo_url, doc_fingerprint)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {ROW_COLS}"
    ))
    .bind(body.full_name.trim())
    .bind(body.organization.as_deref().unwrap_or(""))
    .bind(document_type.as_str())
    .bind(crypto.encrypt(body.document_number.trim())?)
    .bind(crypto.encrypt(body.photo_url.as_deref().unwrap_or(""))?)
    .bind(&fingerprint)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let fp = row.doc_fingerprint.clone();
    let mut app = to_application(&crypto, row)?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("bad kyc row")))?;
    app.prior_decisions = prior_count(&state.pool, &fp, app.id).await?;
    super::routes_audit::record(
        &state.pool, None, "kyc.submitted", "kyc_application", Some(app.id),
        serde_json::json!({"full_name": app.full_name}),
    )
    .await;
    Ok(Json(app))
}

/// Reviewer queue; optional `?status=pending|approved|rejected`.
pub async fn list_kyc(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Query(filter): Query<KycFilter>,
) -> AppResult<Json<Vec<KycApplication>>> {
    require_permission(&state, &user, "kyc:review").await?;
    let status = filter.status.as_deref().unwrap_or("pending");
    if KycStatus::parse(status).is_none() {
        return Err(AppError::BadRequest("status must be pending, approved, or rejected".to_owned()));
    }
    let (limit, offset) = super::paging::resolve(filter.limit, filter.offset, 50)?;
    let pattern = format!("%{}%", filter.q.as_deref().unwrap_or(""));
    let rows: Vec<KycRow> = sqlx::query_as(&format!(
        "SELECT {ROW_COLS} FROM kyc_applications
         WHERE status = $1 AND (full_name ILIKE $2 OR organization ILIKE $2)
         ORDER BY submitted_at LIMIT $3 OFFSET $4"
    ))
    .bind(status)
    .bind(pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let crypto = crypto(&state)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let fp = row.doc_fingerprint.clone();
        if let Some(mut app) = to_application(&crypto, row)? {
            app.prior_decisions = prior_count(&state.pool, &fp, app.id).await?;
            out.push(app);
        }
    }
    Ok(Json(out))
}

/// Approve or reject a pending application. Decided rows are immutable.
pub async fn decide_kyc(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(application_id): Path<Uuid>,
    Json(body): Json<DecideKyc>,
) -> AppResult<Json<KycApplication>> {
    require_permission(&state, &user, "kyc:review").await?;
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
    let crypto = crypto(&state)?;
    let fp = row.doc_fingerprint.clone();
    let mut app = to_application(&crypto, row)?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("bad kyc row")))?;
    app.prior_decisions = prior_count(&state.pool, &fp, app.id).await?;
    super::routes_audit::record(
        &state.pool, Some(user.id), "kyc.decided", "kyc_application", Some(app.id),
        serde_json::json!({"decision": status.as_str()}),
    )
    .await;
    state.hub.publish(&super::events::HubEvent::KycDecided {
        at: chrono::Utc::now(),
        application_id: app.id,
        decision: status.as_str().to_owned(),
    });
    Ok(Json(app))
}

/// Signed press card for an approved application (QR payload for gate scans).
pub async fn press_card(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(application_id): Path<Uuid>,
) -> AppResult<Json<PressCard>> {
    require_permission(&state, &user, "kyc:review").await?;
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
    let card = approved_card(&state, application_id, row)?;
    Ok(Json(card))
}

/// Shared loader: approved row → signed payload (JSON and PNG agree byte-wise).
fn approved_card(
    state: &AppState,
    application_id: Uuid,
    row: KycRow,
) -> AppResult<PressCard> {
    if row.status != KycStatus::Approved.as_str() {
        return Err(AppError::Conflict("press card requires an approved application".to_owned()));
    }
    let _ = application_id;
    Ok(sign_card(&state.jwt_secret, &row))
}

/// QR image of the signed payload: same JSON bytes as `/press-card`,
/// error-correction M, 512px PNG. Gates scan this; kiosk paste stays fallback.
pub async fn press_card_png(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(application_id): Path<Uuid>,
) -> AppResult<impl IntoResponse> {
    require_permission(&state, &user, "kyc:review").await?;
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
    let card = approved_card(&state, application_id, row)?;
    let payload = serde_json::to_string(&card)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("card serialize failed: {e}")))?;
    let code = qrcode::QrCode::with_error_correction_level(
        payload.as_bytes(),
        qrcode::EcLevel::M,
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("qr encode failed: {e}")))?;
    let img = code.render::<image::Luma<u8>>().max_dimensions(512, 512).build();
    let (width, height) = (img.width(), img.height());
    let mut png = Vec::new();
    image::ImageEncoder::write_image(
        image::codecs::png::PngEncoder::new(&mut png),
        &img.into_raw(),
        width,
        height,
        image::ExtendedColorType::L8,
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("png encode failed: {e}")))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "image/png")],
        png,
    ))
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

pub(crate) fn verify_card(secret: &[u8], card: &PressCard) -> bool {
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
