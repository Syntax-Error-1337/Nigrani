use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::core::{AppError, AppResult};
use crate::domain::Role;

const ACCESS_TTL_MINUTES: i64 = 15;
const REFRESH_TTL_DAYS: i64 = 7;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub username: String,
    pub role: String,
    /// Allowlist id: valid only while the matching `access_tokens` row lives.
    pub jti: Uuid,
    pub exp: usize,
    pub iat: usize,
}

pub fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("password hash failed: {e}")))?;
    Ok(hash.to_string())
}

pub fn verify_password(hash: &str, password: &str) -> AppResult<()> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bad password hash: {e}")))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| AppError::Unauthorized("invalid credentials".to_owned()))
}

pub fn issue_access_token(
    secret: &[u8],
    user_id: Uuid,
    username: &str,
    role: Role,
) -> AppResult<(String, Uuid)> {
    let now = Utc::now();
    let jti = Uuid::new_v4();
    let claims = Claims {
        sub: user_id,
        username: username.to_owned(),
        role: role.as_str().to_owned(),
        jti,
        iat: now.timestamp() as usize,
        exp: (now + Duration::minutes(ACCESS_TTL_MINUTES)).timestamp() as usize,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret))
        .map(|token| (token, jti))
        .map_err(|e| AppError::Internal(anyhow::anyhow!("token encode failed: {e}")))
}

pub fn verify_access_token(secret: &[u8], token: &str) -> AppResult<Claims> {
    let data = decode::<Claims>(token, &DecodingKey::from_secret(secret), &Validation::default())
        .map_err(|_| AppError::Unauthorized("invalid or expired token".to_owned()))?;
    Ok(data.claims)
}

pub fn refresh_expiry() -> chrono::DateTime<Utc> {
    Utc::now() + Duration::days(REFRESH_TTL_DAYS)
}

/// Opaque refresh token sent to the client; only its SHA-256 hex is stored.
pub fn new_refresh_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let stored = hex_digest(&token);
    (token, stored)
}

pub fn hex_digest(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode_hex(hasher.finalize())
}

/// Minimal hex encoding without a new dependency.
mod hex {
    pub fn encode_hex(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// RFC 6238 TOTP (SHA-1, 30 s, 6 digits) — the authenticator-app standard.
/// ±1 step tolerance covers clock drift between server and phone.
pub fn totp(secret_base32: &str, at_step: i64) -> AppResult<String> {
    use hmac::Mac;
    use sha1::Sha1;
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_base32.to_ascii_uppercase().as_bytes())
        .map_err(|_| AppError::Internal(anyhow::anyhow!("bad totp secret encoding")))?;
    let mut mac = hmac::Hmac::<Sha1>::new_from_slice(&secret)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("hmac init: {e}")))?;
    mac.update(&(at_step as u64).to_be_bytes());
    let out = mac.finalize().into_bytes();
    let off = (out[19] & 0x0f) as usize;
    let code = (u32::from_be_bytes(out[off..off + 4].try_into().unwrap()) & 0x7fff_ffff) % 1_000_000;
    Ok(format!("{code:06}"))
}

/// Verify a presented code against the secret at ±1 step. Unused steps
/// never validate — a code typed late just needs the current window.
pub fn verify_totp(secret_base32: &str, code: &str) -> AppResult<bool> {
    let step = Utc::now().timestamp() / 30;
    for off in [-1i64, 0, 1] {
        if totp(secret_base32, step + off)? == code {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Fresh base32 secret for enrollment (160 bits — RFC 6238 minimum).
pub fn new_totp_secret() -> String {
    let mut bytes = [0u8; 20];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    data_encoding::BASE32_NOPAD.encode(&bytes)
}
