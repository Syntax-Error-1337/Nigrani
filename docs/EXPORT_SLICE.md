# Export Coherence — Scope Note (t106, sprint s36)

## Gap
`GET /sites/:id/export` froze at the s13/s19 shapes while the live API
moved on: log rows lack the s35 `holder_name/holder_org` (export
consumers matching crossings to people must re-join by application_id
themselves — and CAN'T for purged applications), and gates lack
`archived_at` (an archived gate exports indistinguishably from a live
one — a compliance export that can't tell retired topology from active
is misleading). Export is the compliance surface; staleness here is a
correctness bug, not polish.

## Design
- Gates: select `archived_at`, emit it (null = live). ZeroJOIN cost.
- Logs: `LEFT JOIN kyc_applications` (same as s35 gate_log), emit
  `holder_name`/`holder_org` (null when manual/unlinked).
- Shape stays additive (new keys only — existing consumers parse
  forward-compatibly; the existing export test asserts array-ness, not
  exact keys).
- No frontend change (export is downloaded JSON, not rendered).
- Audit: none (read path).

## Out
CSV export format; signed export bundles; per-incident export.

## Acceptance
- Export on a site with a card crossing + an archived gate shows the
  holder name and the archived timestamp; manual rows show nulls.
- Suite green; clippy clean; live curl proof.
