# Press-Card Revocation — Scope Note (t70, sprint s24)

## Gap
Press cards are pure-HMAC bearer credentials: `verify_card` recomputes the
MAC and returns bool with ZERO database checks. No expiry, no revocation.
An approved journalist later found fraudulent (fake documents discovered
post-approval, credential shared, press org disavows) keeps walking
through every gate — the only recourse today is deactivating the REVIEWER,
which does nothing to the card. The credential lifecycle is issue-only.

## Design
- State: `kyc_applications.card_revoked_at TIMESTAMPTZ NULL`
  (migration `0015`). One timestamp per application (cards re-issued freely
  — each issuance re-signs with fresh `issued_at`; revocation kills the
  APPLICATION's card validity wholesale, which is the correct granularity:
  fraud taints the application, not one QR printout).
- `POST /kyc/applications/:id/revoke-card` (needs `kyc:review`): sets
  `card_revoked_at = now()` on an APPROVED row (pending → 409, missing →
  404, already-revoked → idempotent 200). Audit `kyc.card_revoked`.
  No un-revoke: re-vetting means a fresh application (matches the
  decide-is-immutable doctrine).
- Verify-time enforcement (BOTH paths — this is the actual fix):
  - `POST /kyc/verify` becomes DB-aware: valid HMAC + row exists +
    still approved + `card_revoked_at IS NULL`. Response gains
    `reason` (`"ok" | "bad_signature" | "revoked" | "not_approved"`)
    alongside `valid` (stays bool — old clients keep parsing).
  - `record_event` press_card path: after HMAC verify, check the
    application's live row; revoked/not-approved → 403 (same status as a
    forged card today — scanners already handle it). Manual entries
    unaffected (operator override stays an explicit, audited choice).
- `KycApplication` gains `card_revoked_at` (null default); ReviewDesk
  shows REVOKED badge + Revoke button on approved rows (reuses the
  decision-note input? No — separate confirm-less button; revocation is
  rarer and deliberate. Keep it a single click + audit row).

## Out
Card expiry TTLs (would invalidate ALL outstanding cards at once —
needs re-issuance flow first); per-print serial numbers; OCSP-style
offline CRL distribution to edge scanners.

## Acceptance
- Approve → card verifies ok → revoke → verify says revoked/valid:false;
  gate press_card scan → 403; manual → still 200; revoke pending → 409.
- Suite green; clippy clean; live curl proof.
