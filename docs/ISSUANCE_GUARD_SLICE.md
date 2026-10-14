# Revocation Issuance Guard — Scope Note (t127, sprint s43)

## Gap
s24 revocation kills SCAN-time validity, but issuance (`GET .../press-card`
and `.../press-card.png`, both via `approved_card`) checks status only —
a revoked credential re-prints freely to anyone with `kyc:review`. The
revoke button in ReviewDesk even stays adjacent to a working "Issue press
card" button for revoked rows (frontend hides Revoke when revoked, but
Issue stays). Revocation without an issuance guard is theater on the
re-print path: pull the credential, print a fresh one, walk in.

## Design
- `approved_card`: after the status check, refuse when
  `row.card_revoked_at.is_some()` → 409 "press card revoked" (same
  message family as scan-time; one constant semantic). Both JSON and PNG
  paths inherit (shared loader — single edit).
- ReviewDesk: hide "Issue press card" when `card_revoked_at` is set
  (mirrors the existing Revoke-button hiding; no dead buttons).
- No migration. No new error variant (Conflict exists).
- Audit: none new (refused issuance isn't a mutation; consistent with
  the pending-issue 409 which also doesn't audit).

## Out
Re-vetting flow (fresh application already covers it); issuance audit
trail (no issue event exists today — accepted).

## Acceptance
- Approve → issue 200 → revoke → issue JSON 409 + issue PNG 409 +
  desk hides the button; verify still revoked.
- Suite green; clippy/tsc clean; live curl + UI proof.
