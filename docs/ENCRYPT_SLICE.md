# Encrypted Templates — Scope Note (t28, sprint s10)

## Threat model
DB dumps, backups, and read-only SQL access expose Aadhaar/PAN numbers
and photo references today (`kyc_applications.document_number`,
`photo_url` stored plaintext). Fix: AES-256-GCM at the application layer.

## Design
- New `crypto` module (`backend/src/infrastructure/crypto.rs`, `aes-gcm`
  crate): `encrypt(key, plaintext) -> "v1:<base64 nonce||ciphertext>"`,
  `decrypt` validates prefix + AEAD tag. Random 96-bit nonce per value.
- Key: `BIOMETRIC_KEY` env, 32 raw bytes base64-encoded (44 chars).
  Missing/malformed at boot → KYC + gate-event endpoints fail closed with
  `503 encryption unavailable` (NOT silent plaintext fallback).
- Columns unchanged (TEXT holds the `v1:` envelope — no migration).
  Reads transparently decrypt; undecryptable rows → `500` + log (loud,
  never silent).
- Rotation story: version prefix lets `v2` coexist; rotation job itself
  is recorded OUT (single-key deployment).
- In scope: `document_number`, `photo_url` encrypt-on-write,
  decrypt-on-read (submit, queue, decide, press-card verify path uses
  application_id only — unaffected).
- Out: snapshot JPEG bytes (S3 SSE is the provider's job), embeddings.

## Acceptance
- `SELECT document_number FROM kyc_applications` shows `v1:` ciphertext.
- Full KYC flow (submit → approve → card → gate event) unchanged via API.
- Wrong key → endpoints `503`; tampered ciphertext → `500`, logged.
- Suite green; clippy clean.
