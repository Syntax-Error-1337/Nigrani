# Site-Audit Case Coverage — Scope Note (t97, sprint s33)

## Gap
`GET /sites/:id/audit` resolves rows by `entity_id` against site, gate,
and entry-log ids — but incident audit rows carry `entity_id` = incident
UUID with `entity = 'incident'`. No branch matches, so the ENTIRE case
trail (`incident.created/status/assigned/linked`) is invisible in the
site-scoped view. A site commander reviewing "everything at my site"
sees crossings and topology but zero case work — the forensic story is
split across the SuperAdmin-only global trail.

## Design
- One additional OR branch: `entity_id IN (SELECT id FROM incidents
  WHERE site_id = $1)`. Incidents are site-scoped at creation; the join
  is exact (no detail-JSON mining).
- Also cover snapshot rows? `snapshot.uploaded` / `snapshots.collected`
  carry entity `snapshot` with NULL entity_id (bucket-global, not
  site-scoped) — correctly EXCLUDED. Same for `retention.purge` and
  `demo.reset` (NULL entity_id, global). Only incident rows join.
- No schema change, no new params, ordering unchanged (seq DESC).
- Frontend: no change (AuditTrail already renders whatever the endpoint
  returns; site scope is a prop).

## Out
Detail-JSON site attribution for global rows; per-incident audit view.

## Acceptance
- Site with a full case lifecycle shows ≥4 incident actions in its site
  audit; other-site cases excluded; global-only rows still excluded.
- Suite green; clippy clean; live curl proof.
