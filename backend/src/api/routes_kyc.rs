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
    /// Applicant's consent to biometric identification (required before
    /// their photo may be enrolled as a face embedding).
    pub photo_consent: Option<bool>,
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
    card_revoked_at: Option<Ts>,
    card_serial: Option<String>,
    card_expires_at: Option<Ts>,
    card_print_count: i32,
    // photo_hash is read by scan_duplicates' own SQL; not mapped here.
    // prior_serials is SQL-only (reissue/CRL); not mapped here.
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
        card_revoked_at: row.card_revoked_at,
        card_serial: row.card_serial,
        card_expires_at: row.card_expires_at,
        card_print_count: row.card_print_count,
        duplicates: Vec::new(),
    }))
}

const ROW_COLS: &str = "id, full_name, organization, document_type, document_number, \
    photo_url, status, submitted_at, decided_at, decided_by, decision_note, doc_fingerprint,
    card_revoked_at, card_serial, card_expires_at, card_print_count, prior_serials";

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

// --- Fuzzy duplicate matching + photo-hash duplicates (PII-safe) ---

/// Normalized similarity 0..=1 via edit distance (no new dependency).
fn similarity(a: &str, b: &str) -> f32 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    1.0 - prev[b.len()] as f32 / a.len().max(b.len()) as f32
}

/// SHA-256 hex of photo bytes from a `data:` URL (the only self-contained
/// form a JSON submit can carry). Plain http(s) URLs have no bytes here —
/// skip (their dedupe is the document fingerprint's job).
fn photo_hash_of(photo_url: &str) -> AppResult<Option<String>> {
    let Some(rest) = photo_url.strip_prefix("data:") else {
        return Ok(None);
    };
    let Some((meta, b64)) = rest.split_once(',') else {
        return Err(AppError::BadRequest("photo must be a data: URL with base64 payload".to_owned()));
    };
    if !meta.contains(";base64") {
        return Err(AppError::BadRequest("photo data URL must be base64-encoded".to_owned()));
    }
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| AppError::BadRequest("photo base64 payload malformed".to_owned()))?;
    // Bound the column: 2 MB decoded is generous for a document photo.
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(AppError::BadRequest("photo too large (2 MB max)".to_owned()));
    }
    let digest = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&bytes)
    };
    Ok(Some(digest.iter().map(|b| format!("{b:02x}")).collect()))
}

/// Fuzzy scan against recent rows: name (case/space-insensitive), decrypted
/// document number (normalized), photo hash. Flags ≥0.85; exact photo-hash
/// hits score 1.0. Only ids are persisted — the plaintext never leaves RAM.
async fn scan_duplicates(
    pool: &sqlx::PgPool,
    crypto: &crate::infrastructure::crypto::TemplateCrypto,
    new_id: Uuid,
    new_name: &str,
    new_doc: &str,
    new_photo_hash: Option<&str>,
) -> AppResult<Vec<(Uuid, f32, &'static str)>> {
    const FLOOR: f32 = 0.85;
    let name_key = |s: &str| s.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ");
    let rows: Vec<(Uuid, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, full_name, document_number, photo_hash FROM kyc_applications
         WHERE id <> $1 ORDER BY submitted_at DESC LIMIT 500",
    )
    .bind(new_id)
    .fetch_all(pool)
    .await
    .map_err(AppError::Db)?;
    let mut flags: Vec<(Uuid, f32, &'static str)> = Vec::new();
    for (id, name, doc_number_enc, photo_hash) in rows {
        let doc_number = crypto.decrypt(&doc_number_enc).unwrap_or_default();
        let name_score = similarity(&name_key(new_name), &name_key(&name));
        // Case/space-insensitive document comparison (the blind index
        // normalizes too, but only for exact matches).
        let doc_score = similarity(new_doc.trim().to_uppercase().as_str(), doc_number.trim().to_uppercase().as_str());
        let photo_score = match (new_photo_hash, photo_hash.as_deref()) {
            (Some(a), Some(b)) if a == b => 1.0,
            _ => 0.0,
        };
        let best = [
            (name_score, "name"),
            (doc_score, "document"),
            (photo_score, "photo"),
        ]
        .into_iter()
        .filter(|(s, _)| *s >= FLOOR)
        .max_by(|a, b| a.0.total_cmp(&b.0));
        if let Some((score, reason)) = best {
            flags.push((id, score, reason));
        }
    }
    Ok(flags)
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
    // Photo bytes hashed BEFORE encryption (plain URL → None).
    let photo_hash = photo_hash_of(body.photo_url.as_deref().unwrap_or(""))?;
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
        "INSERT INTO kyc_applications (full_name, organization, document_type, document_number, photo_url, doc_fingerprint, photo_hash, photo_consent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {ROW_COLS}"
    ))
    .bind(body.full_name.trim())
    .bind(body.organization.as_deref().unwrap_or(""))
    .bind(document_type.as_str())
    .bind(crypto.encrypt(body.document_number.trim())?)
    .bind(crypto.encrypt(body.photo_url.as_deref().unwrap_or(""))?)
    .bind(&fingerprint)
    .bind(&photo_hash)
    .bind(body.photo_consent.unwrap_or(false))
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let fp = row.doc_fingerprint.clone();
    let mut app = to_application(&crypto, row)?
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("bad kyc row")))?;
    app.prior_decisions = prior_count(&state.pool, &fp, app.id).await?;
    // Fuzzy scan runs once, at submit, while the plaintext is in hand.
    let flags = scan_duplicates(
        &state.pool,
        &crypto,
        app.id,
        &app.full_name,
        body.document_number.trim(),
        photo_hash.as_deref(),
    )
    .await?;
    for (similar_id, score, reason) in &flags {
        sqlx::query(
            "INSERT INTO kyc_duplicates (application_id, similar_id, score, reason)
             VALUES ($1, $2, $3, $4) ON CONFLICT (application_id, similar_id) DO NOTHING",
        )
        .bind(app.id)
        .bind(similar_id)
        .bind(score)
        .bind(reason)
        .execute(&state.pool)
        .await
        .map_err(AppError::Db)?;
    }
    app.duplicates = flags
        .into_iter()
        .map(|(similar_id, score, reason)| crate::domain::DuplicateFlag {
            similar_id,
            score,
            reason: reason.to_owned(),
        })
        .collect();
    if !app.duplicates.is_empty() {
        super::routes_audit::record(
            &state.pool,
            None,
            "kyc.duplicate_flagged",
            "kyc_application",
            Some(app.id),
            serde_json::json!({"count": app.duplicates.len()}),
        )
        .await;
    }
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
         ORDER BY submitted_at DESC LIMIT $3 OFFSET $4"
    ))
    .bind(status)
    .bind(pattern)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let crypto = crypto(&state)?;
    // One flag query for the whole page (ids only — no PII handling here).
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut flags_by_app: std::collections::HashMap<Uuid, Vec<crate::domain::DuplicateFlag>> =
        std::collections::HashMap::new();
    if !ids.is_empty() {
        let flag_rows: Vec<(Uuid, Uuid, f32, String)> = sqlx::query_as(
            "SELECT application_id, similar_id, score, reason
             FROM kyc_duplicates WHERE application_id = ANY($1)",
        )
        .bind(&ids)
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Db)?;
        for (application_id, similar_id, score, reason) in flag_rows {
            flags_by_app.entry(application_id).or_default().push(crate::domain::DuplicateFlag {
                similar_id,
                score,
                reason,
            });
        }
    }
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let fp = row.doc_fingerprint.clone();
        if let Some(mut app) = to_application(&crypto, row)? {
            app.prior_decisions = prior_count(&state.pool, &fp, app.id).await?;
            app.duplicates = flags_by_app.remove(&app.id).unwrap_or_default();
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
    // Rejections without recourse are dead ends: require an actionable note
    // (approvals need none — the card is the outcome).
    if status == KycStatus::Rejected && body.note.as_deref().unwrap_or("").trim().len() < 3 {
        return Err(AppError::BadRequest("rejection requires a note".to_owned()));
    }
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

/// Revoke an application's press card (fraud discovered post-approval,
/// credential shared, org disavows). Approved-only; idempotent; no un-revoke.
pub async fn revoke_card(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(application_id): Path<Uuid>,
) -> AppResult<Json<KycApplication>> {
    require_permission(&state, &user, "kyc:review").await?;
    let row: Option<KycRow> = sqlx::query_as(&format!(
        "UPDATE kyc_applications SET card_revoked_at = now()
         WHERE id = $1 AND status = 'approved' RETURNING {ROW_COLS}"
    ))
    .bind(application_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let Some(row) = row else {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM kyc_applications WHERE id = $1)")
            .bind(application_id)
            .fetch_one(&state.pool)
            .await
            .map_err(AppError::Db)?;
        return Err(if exists {
            AppError::Conflict("press card requires an approved application".to_owned())
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
        &state.pool, Some(user.id), "kyc.card_revoked", "kyc_application", Some(app.id),
        serde_json::json!({}),
    )
    .await;
    Ok(Json(app))
}

/// Re-issue an approved press card: bumps print_count, rotates the serial,
/// refreshes the 90-day expiry. The outgoing serial moves to `prior_serials`
/// so scans of it answer `superseded` and the CRL lists it; single-statement
/// mint keeps concurrent reissues race-safe.
pub async fn reissue_card(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
    Path(application_id): Path<Uuid>,
) -> AppResult<Json<KycApplication>> {
    require_permission(&state, &user, "kyc:review").await?;
    let expires_at = Utc::now() + chrono::Duration::days(CARD_VALIDITY_DAYS);
    let row: Option<KycRow> = sqlx::query_as(&format!(
        "UPDATE kyc_applications SET
            card_print_count = card_print_count + 1,
            card_serial = {NEXT_SERIAL_SQL},
            card_expires_at = $2,
            prior_serials = CASE WHEN card_serial IS NULL THEN prior_serials
                                 ELSE array_append(prior_serials, card_serial) END
         WHERE id = $1 AND status = 'approved' AND card_revoked_at IS NULL
         RETURNING {ROW_COLS}"
    ))
    .bind(application_id)
    .bind(expires_at)
    .fetch_optional(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let Some(row) = row else {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM kyc_applications WHERE id = $1)")
            .bind(application_id)
            .fetch_one(&state.pool)
            .await
            .map_err(AppError::Db)?;
        return Err(if exists {
            AppError::Conflict("reissue requires an approved, unrevoked application".to_owned())
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
        &state.pool, Some(user.id), "kyc.card_reissued", "kyc_application", Some(app.id),
        serde_json::json!({"serial": app.card_serial}),
    )
    .await;
    Ok(Json(app))
}

/// Offline CRL export: every credential class a gate must refuse — revoked,
/// expired, superseded serials — as a downloadable JSON attachment for
/// checkpoints without live DB access.
pub async fn export_crl(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> AppResult<impl IntoResponse> {
    // Reviewers export the CRL normally; gate operators may fetch it to
    // keep an offline deny list at the kiosk (see Kiosk offline mode).
    let granted = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
            SELECT 1 FROM users u
            JOIN roles r ON r.id = u.role_id
            JOIN role_permissions rp ON rp.role_id = r.id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE u.id = $1 AND p.name IN ('kyc:review', 'entries:write')
        )",
    )
    .bind(user.id)
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Db)?;
    if !granted {
        return Err(AppError::Forbidden(
            "kyc:review or entries:write required".to_owned(),
        ));
    }
    let revoked: Vec<(Uuid, Option<String>, Ts)> = sqlx::query_as(
        "SELECT id, card_serial, card_revoked_at FROM kyc_applications
         WHERE card_revoked_at IS NOT NULL ORDER BY id",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let expired: Vec<(Uuid, Option<String>, Ts)> = sqlx::query_as(
        "SELECT id, card_serial, card_expires_at FROM kyc_applications
         WHERE status = 'approved' AND card_revoked_at IS NULL
           AND card_expires_at IS NOT NULL AND card_expires_at < now()
         ORDER BY id",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    // One row per prior serial; empty arrays unnest to nothing.
    let superseded: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, s FROM kyc_applications, unnest(prior_serials) AS s ORDER BY id, s",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Db)?;
    let entry = |(id, serial, since): &(Uuid, Option<String>, Ts)| {
        serde_json::json!({ "application_id": id, "serial": serial, "since": since })
    };
    let body = serde_json::json!({
        "generated_at": Utc::now(),
        "revoked": revoked.iter().map(entry).collect::<Vec<_>>(),
        "expired": expired.iter().map(entry).collect::<Vec<_>>(),
        "superseded": superseded
            .iter()
            .map(|(id, serial)| serde_json::json!({ "application_id": id, "serial": serial }))
            .collect::<Vec<_>>(),
    });
    super::routes_audit::record(
        &state.pool, Some(user.id), "kyc.crl_exported", "kyc_application", None,
        serde_json::json!({}),
    )
    .await;
    let filename = format!("crl-{}.json", Utc::now().format("%Y-%m-%d"));
    Ok((
        [
            (axum::http::header::CONTENT_TYPE, "application/json".to_owned()),
            (axum::http::header::CACHE_CONTROL, "no-store".to_owned()),
            (axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
        ],
        body.to_string(),
    ))
}

/// Row projection for scan-time liveness.
#[derive(Debug, sqlx::FromRow)]
struct CardLiveness {
    status: String,
    card_revoked_at: Option<Ts>,
    card_serial: Option<String>,
    card_expires_at: Option<Ts>,
}

/// Card liveness for scan-time enforcement: HMAC must verify AND the
/// application row must still approve AND not be revoked AND not be expired
/// AND carry the current serial.
pub async fn card_status(
    pool: &sqlx::PgPool,
    secret: &[u8],
    card: &PressCard,
) -> (&'static str, bool) {
    if !verify_card(secret, card) {
        return ("bad_signature", false);
    }
    let row: Option<CardLiveness> = sqlx::query_as(
        "SELECT status, card_revoked_at, card_serial, card_expires_at
         FROM kyc_applications WHERE id = $1",
    )
    .bind(card.application_id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    match row {
        None => ("not_approved", false),
        Some(live) if live.status != KycStatus::Approved.as_str() => ("not_approved", false),
        Some(live) if live.card_revoked_at.is_some() => ("revoked", false),
        Some(live) => {
            if live.card_expires_at.is_some_and(|at| at < Utc::now()) {
                return ("expired", false);
            }
            // Superseded: presented serial is not the row's current one. A
            // pre-lifecycle row (NULL serial) only accepts serial-less cards.
            let superseded = match live.card_serial {
                None => card.serial.is_some(),
                Some(current) => card.serial.as_deref() != Some(current.as_str()),
            };
            if superseded {
                return ("superseded", false);
            }
            ("ok", true)
        }
    }
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
    let card = approved_card(&state, row).await?;
    Ok(Json(card))
}

/// Shared loader: approved row → lazily mint serial/expiry on first print →
/// signed payload (JSON and PNG agree byte-wise).
async fn approved_card(state: &AppState, row: KycRow) -> AppResult<PressCard> {
    if row.status != KycStatus::Approved.as_str() {
        return Err(AppError::Conflict("press card requires an approved application".to_owned()));
    }
    // Revoked credentials never re-print (scan-time already refuses them;
    // issuance must agree or revocation is theater).
    if row.card_revoked_at.is_some() {
        return Err(AppError::Conflict("press card revoked".to_owned()));
    }
    let row = mint_serial(&state.pool, row).await?;
    Ok(sign_card(&state.jwt_secret, &row))
}

/// Press-card validity window from issuance/reissue; scans past it are
/// `expired` until reissued.
const CARD_VALIDITY_DAYS: i64 = 90;

/// Serial expression for the NEXT print: `SG-<8 hex of application id>-<print
/// count>`. All UPDATE right-hand sides see the pre-update row, hence + 1 —
/// which also makes concurrent mints serialize correctly on one row.
const NEXT_SERIAL_SQL: &str =
    "'SG-' || left(replace(id::text, '-', ''), 8) || '-' || (card_print_count + 1)";

/// First print lazily mints serial + expiry in one guarded UPDATE; a print
/// that loses the race re-reads and reuses the winner's serial (never two).
async fn mint_serial(pool: &sqlx::PgPool, row: KycRow) -> AppResult<KycRow> {
    if row.card_serial.is_some() {
        return Ok(row);
    }
    let expires_at = Utc::now() + chrono::Duration::days(CARD_VALIDITY_DAYS);
    let minted: Option<KycRow> = sqlx::query_as(&format!(
        "UPDATE kyc_applications
         SET card_serial = {NEXT_SERIAL_SQL}, card_expires_at = $2,
             card_print_count = card_print_count + 1
         WHERE id = $1 AND card_serial IS NULL
         RETURNING {ROW_COLS}"
    ))
    .bind(row.id)
    .bind(expires_at)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Db)?;
    match minted {
        Some(row) => Ok(row),
        None => {
            sqlx::query_as(&format!("SELECT {ROW_COLS} FROM kyc_applications WHERE id = $1"))
                .bind(row.id)
                .fetch_optional(pool)
                .await
                .map_err(AppError::Db)?
                .ok_or_else(|| AppError::NotFound("application not found".to_owned()))
        }
    }
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
    let card = approved_card(&state, row).await?;
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
    // Lazy mint guarantees these exist on every signed card.
    let serial = row.card_serial.clone().expect("serial minted before signing");
    let expires_at = row.card_expires_at.expect("expiry minted before signing");
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(row.id.as_bytes());
    mac.update(row.full_name.as_bytes());
    mac.update(row.organization.as_bytes());
    mac.update(serial.as_bytes());
    mac.update(expires_at.timestamp().to_be_bytes().as_ref());
    mac.update(issued_at.timestamp().to_be_bytes().as_ref());
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(mac.finalize().into_bytes());
    PressCard {
        application_id: row.id,
        full_name: row.full_name.clone(),
        organization: row.organization.clone(),
        v: 1,
        serial: Some(serial),
        expires_at: Some(expires_at),
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
    let (reason, valid) = card_status(&state.pool, &state.jwt_secret, &card).await;
    Ok(Json(serde_json::json!({ "valid": valid, "reason": reason, "application_id": card.application_id })))
}

pub(crate) fn verify_card(secret: &[u8], card: &PressCard) -> bool {
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(card.application_id.as_bytes());
    mac.update(card.full_name.as_bytes());
    mac.update(card.organization.as_bytes());
    // v0 payloads (serial AND expiry absent) are pre-lifecycle cards signed
    // with the legacy recipe; anything carrying a serial verifies as v1.
    let legacy = card.serial.is_none() && card.expires_at.is_none() && card.v == 0;
    if !legacy {
        mac.update(card.serial.as_deref().unwrap_or("").as_bytes());
        mac.update(card.expires_at.map(|t| t.timestamp()).unwrap_or(0).to_be_bytes().as_ref());
    }
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
