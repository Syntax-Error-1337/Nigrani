# Crossing Identity Display — Scope Note (t103, sprint s35)

## Gap
Gate-log rows carry `application_id` (UUID) but no holder identity: the
kiosk "Recent crossings" list shows `ENTRY card 14:02:11` with no WHO.
During a rush the operator cannot visually confirm the right journalist
just crossed — the one human question the log exists to answer. The name
lives one JOIN away (`kyc_applications.full_name`), plaintext (names were
never encrypted — only document numbers + photos).

## Design
- `EntryLog` gains `holder_name: Option<String>` + `holder_org:
  Option<String>` (serde default → old cached JSON parses; None for
  manual entries and purged/unlinked applications).
- Single-query LEFT JOIN in `gate_log` (no N+1): `LEFT JOIN
  kyc_applications k ON k.id = l.application_id`, selecting
  `k.full_name, k.organization`. `record_event`'s RETURNING row: same
  join is awkward on INSERT...RETURNING — instead re-SELECT the joined
  row by id after insert (one extra indexed point-lookup, keeps the
  response shape identical for both paths).
- Kiosk renders `holder_name (org)` after the method badge, em-dash
  separated; manual rows unchanged (no holder).
- PII posture unchanged: names are already visible to every role with
  `gates:read` via the reviewer queue + press cards; log viewers hold the
  same permission.

## Out
Photo thumbnails inline in rows (preview button already exists);
holder-name search on the log; redaction mode for public displays.

## Acceptance
- Card crossing returns holder name+org in POST response AND log list;
  manual crossing returns nulls; kiosk shows the name.
- Suite green; clippy/tsc clean; live curl + UI proof.
