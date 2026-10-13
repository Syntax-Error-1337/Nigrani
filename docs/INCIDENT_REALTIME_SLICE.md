# Incident Realtime + Coverage — Scope Note (t55, sprint s19)

## Gap
Incident mutations are REST-silent: create/transition/assign/link publish
nothing on the WS hub, so a second analyst's bench goes stale mid-case.
Coverage drift too: `run_purge` skips `incidents`/`incident_links`
entirely (no policy rows, no purge lines), `export_site` omits
status/assignee/links, and `reset_demo` TRUNCATEs `incidents` but never
names `incident_links` (works today only via CASCADE).

## Design
- `HubEvent::Incident { at, site_id, incident_id, action }` where action ∈
  `created|status|assigned|linked`. Publish in the four handlers AFTER the
  audit record (same best-effort position as crossing/topology publishes —
  hub first would lie on DB failure; audit-record failure never blocks).
- Purge: seed policy rows for `incidents` (365d) and `incident_links`
  (365d); purge children-first (links → incidents). Incidents keyed on
  `created_at`, links on `added_at`. Needs a migration (INSERTs into
  `retention_policies` — check seeder shape first).
- Export: incidents carry `status`, `assigned_to`, `resolved_at`; add an
  `incident_links` array (id/kind/ref_id/note/added_at, capped 500).
- Reset: name `incident_links` before `incidents` in the table list
  (explicit > CASCADE-luck; CASCADE keeps it green either way).

## Out
Per-user WS filtering (bench subscribes to all site noise today), SLA
timers, replay/catch-up cursors.

## Acceptance
- WS subscriber receives 4 incident events across a create→status→assign→
  link flow; kinds/actions asserted on the wire JSON.
- Purge with retain_days=0 refuses (existing guard) — set 1 day + backdate
  one incident + link, purge deletes both; export shows status + links;
  reset truncates both (report keys asserted).
- Suite green; clippy clean; live WS + curl proof.
