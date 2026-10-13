# Capture Review — Scope Note (t46, sprint s16)

## Gap
Captures exist but are invisible: gate snapshots sit in S3 keyed only on
log rows (kiosk shows the key, never the image), and KYC `photo_url`
(usually a snapshot key or external URL) never renders in the review
desk. Reviewers decide on text alone.

## Design
- Kiosk log rows with `snapshot_key`: thumbnail via the existing
  `/snapshots/:key/share` presigned URL (15-min; fetched on row expand,
  not eagerly — keeps list loads cheap). Click row → overlay with full
  image + entry facts (direction, method, time).
- ReviewDesk rows: if `photo_url` is non-empty, show "photo" affordance:
  `v1:`-envelope impossible (photo_url holds keys/URLs, may itself be
  encrypted — decrypt first, then decide: `s3://` or raw key →
  presigned via `/snapshots/:key/share`; `http(s)://` → direct link;
  else plain text).
- No backend changes expected (share + log endpoints suffice); slice is
  frontend-only unless a gap surfaces.

## PII handling
Images render only for roles already holding `gates:read`/`kyc:review`;
presigned URLs expire in 15 min; no image bytes through the API.

## Acceptance
- Log an entry with snapshot → thumbnail + overlay render in kiosk.
- ReviewDesk shows photo affordance for photo-bearing applications.
- Suite green (no backend change → backend suite untouched); tsc/oxlint
  clean; browser screenshots both.
