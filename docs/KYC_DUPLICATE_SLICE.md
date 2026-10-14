# KYC Duplicate Detection — Scope Note (t58, sprint s20)

## Gap
`submit_kyc` is append-only: the same document number resubmits forever
(queue spam by refresh-loop or bot). Document numbers are AES-256-GCM
ciphertexts with random nonces, so SQL equality can never match — no
UNIQUE constraint is possible on the column. The reviewer queue shows no
duplicate signal either.

## Design
- Blind index: `kyc_applications.doc_fingerprint TEXT` = hex(HMAC-SHA256(
  key=BIOMETRIC_KEY, normalized `document_type + '|' + document_number`)).
  Normalization: trim + uppercase (PAN/Aadhaar are case-insensitive
  identifiers; `pan|abc123` == `pan| ABC123 `). HMAC (not SHA-256) so a
  DB leak doesn't enable offline document-number enumeration.
- Migration `0011`: ADD COLUMN `doc_fingerprint TEXT NOT NULL DEFAULT ''`
  + index. Backfill: undecryptable legacy rows keep `''` (fail-open for
  old rows only; new submits always fingerprinted). Follow-up may add a
  partial UNIQUE index once backfill is trusted — NOT this slice (would
  hard-fail backfill races; behavior stays application-level).
- Submit: compute fingerprint; if a `pending` row with the same
  fingerprint exists → `409 Conflict("a pending application already exists
  for this document")`. Decided rows (approved/rejected) do NOT block —
  re-application after rejection is legitimate; instead the response
  carries no extra field (keep the submit contract stable).
- Reviewer signal: `KycApplication` gains `prior_decisions: i64` (count of
  non-pending rows with the same fingerprint, excluding self). List +
  decide responses populate it. Zero for first-timers — cheap
  (`SELECT COUNT(*)`, indexed equality) and visible in ReviewDesk as
  "repeat applicant ×N".
- Audit: duplicate-blocked submits record `kyc.duplicate_blocked`
  (actor None, public endpoint) with the fingerprint prefix (8 hex chars
  — enough to correlate, useless to reverse).

## Out
Partial UNIQUE index on (doc_fingerprint) WHERE status='pending' (race-hard);
fuzzy matching (name+dob); cross-document-type alias detection; photo-hash
duplicates.

## Acceptance
- Submit A → 200; submit A again (different case/spacing) → 409; decide
  A rejected → submit A → 200 with prior_decisions=1; approve path keeps
  prior count visible in list.
- Reviewer UI shows the repeat-applicant badge.
- Suite green; clippy clean; live curl proof.
