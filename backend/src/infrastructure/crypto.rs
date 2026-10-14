//! Application-layer encryption for biometric-adjacent PII
//! (KYC document numbers, photo references): AES-256-GCM, random 96-bit
//! nonce per value, `v1:<base64 nonce||ciphertext>` envelope in TEXT columns.
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use base64::Engine;
use rand::RngCore;

use crate::core::{AppError, AppResult};

const PREFIX: &str = "v1:";

#[derive(Clone)]
pub struct TemplateCrypto {
    cipher: Aes256Gcm,
    /// Raw key, retained for the document blind index (HMAC-SHA256).
    /// Same secrecy as the cipher itself — never logged or serialized.
    key: [u8; 32],
}

impl TemplateCrypto {
    /// Load from `BIOMETRIC_KEY` env (base64 of 32 raw bytes).
    pub fn from_env() -> AppResult<Self> {
        let raw = std::env::var("BIOMETRIC_KEY").map_err(|_| {
            AppError::Internal(anyhow::anyhow!(
                "BIOMETRIC_KEY not set; KYC endpoints unavailable"
            ))
        })?;
        Self::from_base64(&raw)
    }

    pub fn from_base64(b64: &str) -> AppResult<Self> {
        use base64::engine::general_purpose::STANDARD;
        let bytes = STANDARD.decode(b64.trim()).map_err(|_| {
            AppError::Internal(anyhow::anyhow!("BIOMETRIC_KEY is not valid base64"))
        })?;
        if bytes.len() != 32 {
            return Err(AppError::Internal(anyhow::anyhow!(
                "BIOMETRIC_KEY must decode to 32 bytes"
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        let cipher = Aes256Gcm::new(&aes_gcm::Key::<Aes256Gcm>::from(key));
        Ok(Self { cipher, key })
    }

    /// Blind index over a normalized document identity
    /// (`document_type|NUMBER`, uppercased + trimmed by callers):
    /// base64(HMAC-SHA256(key, input)). HMAC (not plain hash) so a DB leak
    /// doesn't enable offline document-number enumeration.
    pub fn fingerprint(&self, normalized: &str) -> String {
        use base64::Engine as _;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("hmac accepts any key length");
        mac.update(normalized.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
    }

    pub fn encrypt(&self, plaintext: &str) -> AppResult<String> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let ct = self
            .cipher
            .encrypt(
                &aes_gcm::Nonce::try_from(nonce_bytes.as_slice()).expect("12-byte nonce"),
                plaintext.as_bytes(),
            )
            .map_err(|e| AppError::Internal(anyhow::anyhow!("encrypt failed: {e}")))?;
        let mut blob = Vec::with_capacity(12 + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        Ok(format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        ))
    }

    pub fn decrypt(&self, envelope: &str) -> AppResult<String> {
        // Legacy fallback: rows written before encryption went live hold
        // plaintext. They pass through with a warning so reads keep working;
        // all new writes are envelopes. (A backfill would need the key at
        // migration time — recorded out of scope.)
        let Some(b64) = envelope.strip_prefix(PREFIX) else {
            // A `vN:`-shaped value that is NOT v1 is a version mismatch, never
            // legacy data — fail closed so future envelopes can't downgrade.
            if envelope.len() > 3 && envelope.as_bytes()[0] == b'v' && envelope.as_bytes()[3] == b':' {
                return Err(AppError::Internal(anyhow::anyhow!("unsupported ciphertext version")));
            }
            tracing::warn!("decrypting legacy plaintext row; re-submit to encrypt");
            return Ok(envelope.to_owned());
        };
        let blob = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| AppError::Internal(anyhow::anyhow!("bad ciphertext encoding")))?;
        if blob.len() < 12 + 16 {
            return Err(AppError::Internal(anyhow::anyhow!("ciphertext too short")));
        }
        let (nonce_bytes, ct) = blob.split_at(12);
        let pt = self
            .cipher
            .decrypt(
                &aes_gcm::Nonce::try_from(nonce_bytes).expect("12-byte nonce"),
                ct,
            )
            .map_err(|_| {
                AppError::Internal(anyhow::anyhow!("decryption failed (wrong key or tampered data)"))
            })?;
        String::from_utf8(pt)
            .map_err(|_| AppError::Internal(anyhow::anyhow!("decrypted bytes are not UTF-8")))
    }

    /// Decrypt on read; empty stored values stay empty (pre-encryption rows).
    pub fn decrypt_opt(&self, envelope: &str) -> AppResult<String> {
        if envelope.is_empty() {
            Ok(String::new())
        } else {
            self.decrypt(envelope)
        }
    }
}
